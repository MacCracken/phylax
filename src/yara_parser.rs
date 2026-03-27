//! Native YARA (.yar) syntax parser.
//!
//! Parses standard YARA rule files into internal [`YaraRule`] representations
//! compatible with the [`YaraEngine`] scanner.
//!
//! Supports: rule declarations with tags, meta sections, string definitions
//! (text, hex with wildcards, regex) with modifiers (nocase, wide, ascii),
//! and boolean condition expressions.
//!
//! `import` statements are silently skipped (module system not yet supported).

use crate::yara::{CmpOp, ConditionExpr, YaraError, YaraPattern};
use std::collections::HashMap;

/// A parsed YARA rule before conversion to the engine's internal format.
#[derive(Debug)]
pub struct ParsedYaraRule {
    pub name: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub patterns: Vec<(String, YaraPattern)>,
    pub condition: ConditionExpr,
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Rule,
    Meta,
    Strings,
    Condition,
    Import,
    True,
    False,
    And,
    Or,
    Not,
    All,
    Any,
    Of,
    Them,
    Filesize,
    For,
    In,
    At,
    DotDot, // ..
    Nocase,
    Wide,
    Ascii,
    Fullword,
    // Identifiers & literals
    Ident(String),
    PatternId(String),       // $name
    PatternCountId(String),  // #name (count of matches)
    PatternOffsetId(String), // @name (offset of match)
    StringLit(String),
    HexBlock(String),
    RegexLit(String),
    IntLit(u64),
    // Delimiters & operators
    LBracket, // [
    RBracket, // ]
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Equals,
    Lt,
    Gt,
    Le,
    Ge,
    EqEq,
    Ne,
    Comma,
    Eof,
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

struct Lexer {
    chars: Vec<char>,
    pos: usize,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.peek_char().is_some_and(|c| c.is_ascii_whitespace()) {
                self.next_char();
            }

            // Single-line comment: //
            if self.pos + 1 < self.chars.len()
                && self.chars[self.pos] == '/'
                && self.chars[self.pos + 1] == '/'
            {
                while self.peek_char().is_some_and(|c| c != '\n') {
                    self.next_char();
                }
                continue;
            }

            // Multi-line comment: /* */
            if self.pos + 1 < self.chars.len()
                && self.chars[self.pos] == '/'
                && self.chars[self.pos + 1] == '*'
            {
                self.pos += 2;
                while self.pos + 1 < self.chars.len() {
                    if self.chars[self.pos] == '*' && self.chars[self.pos + 1] == '/' {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
                continue;
            }

            break;
        }
    }

    /// Check if the current position looks like the start of a hex block content.
    /// Hex blocks contain: 2-char hex pairs, ??, (, [.
    /// Rule bodies contain keywords that are longer than 2 hex-like chars.
    fn peek_is_hex_block_start(&self) -> bool {
        let mut i = self.pos;
        // Skip to first non-whitespace
        while i < self.chars.len() && self.chars[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= self.chars.len() {
            return false;
        }
        let c = self.chars[i];

        // Definitely hex: ? or ( or [
        if c == '?' || c == '(' || c == '[' {
            return true;
        }

        // Could be hex digit — check if it's a 2-char hex pair followed by
        // whitespace/}/?/hex, NOT a longer identifier
        if c.is_ascii_hexdigit()
            && i + 1 < self.chars.len()
            && self.chars[i + 1].is_ascii_hexdigit()
        {
            // Check the char after the pair
            if i + 2 >= self.chars.len() {
                return true;
            }
            let after = self.chars[i + 2];
            // If the pair is followed by more alphanumeric chars, it's an identifier
            return !after.is_ascii_alphanumeric() && after != '_';
        }

        false
    }

    fn next_token(&mut self) -> crate::yara::Result<Token> {
        self.skip_whitespace_and_comments();

        let ch = match self.peek_char() {
            None => return Ok(Token::Eof),
            Some(c) => c,
        };

        // Pattern ID: $identifier
        if ch == '$' {
            self.next_char();
            let mut name = String::from("$");
            while self
                .peek_char()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                name.push(self.next_char().unwrap());
            }
            return Ok(Token::PatternId(name));
        }

        // Pattern count: #identifier
        if ch == '#'
            && self.pos + 1 < self.chars.len()
            && self.chars[self.pos + 1].is_ascii_alphabetic()
        {
            self.next_char();
            let mut name = String::from("$"); // normalize to $ prefix for lookup
            while self
                .peek_char()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                name.push(self.next_char().unwrap());
            }
            return Ok(Token::PatternCountId(name));
        }

        // Pattern offset: @identifier
        if ch == '@' {
            self.next_char();
            let mut name = String::from("$"); // normalize to $ prefix for lookup
            while self
                .peek_char()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                name.push(self.next_char().unwrap());
            }
            return Ok(Token::PatternOffsetId(name));
        }

        // String literal: "..."
        if ch == '"' {
            return self.lex_string_literal();
        }

        // Hex block: { ... }
        if ch == '{' {
            // Distinguish hex block from rule body brace.
            // Hex blocks start with hex pairs (2-char), ??, (, or [.
            // Rule bodies start with keywords (meta, strings, condition, }).
            let saved = self.pos;
            self.next_char();
            self.skip_whitespace_and_comments();
            let is_hex = self.peek_is_hex_block_start();
            self.pos = saved;

            if is_hex {
                return self.lex_hex_block();
            }
            self.next_char();
            return Ok(Token::LBrace);
        }

        // Regex literal: /pattern/
        if ch == '/' {
            return self.lex_regex_literal();
        }

        // Operators
        match ch {
            '}' => {
                self.next_char();
                return Ok(Token::RBrace);
            }
            '(' => {
                self.next_char();
                return Ok(Token::LParen);
            }
            ')' => {
                self.next_char();
                return Ok(Token::RParen);
            }
            '[' => {
                self.next_char();
                return Ok(Token::LBracket);
            }
            ']' => {
                self.next_char();
                return Ok(Token::RBracket);
            }
            ':' => {
                self.next_char();
                return Ok(Token::Colon);
            }
            ',' => {
                self.next_char();
                return Ok(Token::Comma);
            }
            '.' => {
                self.next_char();
                if self.peek_char() == Some('.') {
                    self.next_char();
                    return Ok(Token::DotDot);
                }
                return Err(YaraError::Parse("unexpected '.'".into()));
            }
            '<' => {
                self.next_char();
                if self.peek_char() == Some('=') {
                    self.next_char();
                    return Ok(Token::Le);
                }
                return Ok(Token::Lt);
            }
            '>' => {
                self.next_char();
                if self.peek_char() == Some('=') {
                    self.next_char();
                    return Ok(Token::Ge);
                }
                return Ok(Token::Gt);
            }
            '=' => {
                self.next_char();
                if self.peek_char() == Some('=') {
                    self.next_char();
                    return Ok(Token::EqEq);
                }
                return Ok(Token::Equals);
            }
            '!' => {
                self.next_char();
                if self.peek_char() == Some('=') {
                    self.next_char();
                    return Ok(Token::Ne);
                }
                return Err(YaraError::Parse("unexpected '!'".into()));
            }
            _ => {}
        }

        // Integer literal
        if ch.is_ascii_digit() {
            return self.lex_integer();
        }

        // Identifier or keyword
        if ch.is_ascii_alphabetic() || ch == '_' {
            return self.lex_ident_or_keyword();
        }

        Err(YaraError::Parse(format!("unexpected character: '{ch}'")))
    }

    fn lex_string_literal(&mut self) -> crate::yara::Result<Token> {
        self.next_char(); // consume opening "
        let mut s = String::new();
        loop {
            match self.next_char() {
                None => return Err(YaraError::Parse("unterminated string literal".into())),
                Some('"') => return Ok(Token::StringLit(s)),
                Some('\\') => match self.next_char() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some(c) => {
                        s.push('\\');
                        s.push(c);
                    }
                    None => return Err(YaraError::Parse("unterminated escape".into())),
                },
                Some(c) => s.push(c),
            }
        }
    }

    fn lex_hex_block(&mut self) -> crate::yara::Result<Token> {
        self.next_char(); // consume opening {
        let mut hex = String::new();
        loop {
            match self.next_char() {
                None => return Err(YaraError::Parse("unterminated hex block".into())),
                Some('}') => return Ok(Token::HexBlock(hex.trim().to_string())),
                Some(c) => hex.push(c),
            }
        }
    }

    fn lex_regex_literal(&mut self) -> crate::yara::Result<Token> {
        self.next_char(); // consume opening /
        let mut re = String::new();
        loop {
            match self.next_char() {
                None => return Err(YaraError::Parse("unterminated regex literal".into())),
                Some('/') => return Ok(Token::RegexLit(re)),
                Some('\\') => {
                    re.push('\\');
                    if let Some(c) = self.next_char() {
                        re.push(c);
                    }
                }
                Some(c) => re.push(c),
            }
        }
    }

    fn lex_integer(&mut self) -> crate::yara::Result<Token> {
        let mut digits = String::new();
        // Handle 0x prefix
        if self.peek_char() == Some('0')
            && self.pos + 1 < self.chars.len()
            && (self.chars[self.pos + 1] == 'x' || self.chars[self.pos + 1] == 'X')
        {
            self.next_char(); // 0
            self.next_char(); // x
            while self.peek_char().is_some_and(|c| c.is_ascii_hexdigit()) {
                digits.push(self.next_char().unwrap());
            }
            let val = u64::from_str_radix(&digits, 16)
                .map_err(|_| YaraError::Parse(format!("invalid hex integer: 0x{digits}")))?;
            return Ok(Token::IntLit(val));
        }

        while self.peek_char().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(self.next_char().unwrap());
        }
        let mut val: u64 = digits
            .parse()
            .map_err(|_| YaraError::Parse(format!("invalid integer: {digits}")))?;

        // Size suffixes
        if self.peek_char() == Some('K') || self.peek_char() == Some('k') {
            self.next_char();
            if self.peek_char() == Some('B') || self.peek_char() == Some('b') {
                self.next_char();
            }
            val *= 1024;
        } else if self.peek_char() == Some('M') || self.peek_char() == Some('m') {
            self.next_char();
            if self.peek_char() == Some('B') || self.peek_char() == Some('b') {
                self.next_char();
            }
            val *= 1024 * 1024;
        }

        Ok(Token::IntLit(val))
    }

    fn lex_ident_or_keyword(&mut self) -> crate::yara::Result<Token> {
        let mut ident = String::new();
        while self
            .peek_char()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            ident.push(self.next_char().unwrap());
        }

        let tok = match ident.as_str() {
            "rule" => Token::Rule,
            "meta" => Token::Meta,
            "strings" => Token::Strings,
            "condition" => Token::Condition,
            "import" => Token::Import,
            "true" => Token::True,
            "false" => Token::False,
            "and" => Token::And,
            "or" => Token::Or,
            "not" => Token::Not,
            "all" => Token::All,
            "any" => Token::Any,
            "of" => Token::Of,
            "them" => Token::Them,
            "filesize" => Token::Filesize,
            "for" => Token::For,
            "in" => Token::In,
            "at" => Token::At,
            "nocase" => Token::Nocase,
            "wide" => Token::Wide,
            "ascii" => Token::Ascii,
            "fullword" => Token::Fullword,
            _ => Token::Ident(ident),
        };
        Ok(tok)
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(lexer: &mut Lexer) -> crate::yara::Result<Self> {
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token()?;
            let is_eof = tok == Token::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(Self { tokens, pos: 0 })
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let tok = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, expected: &Token) -> crate::yara::Result<()> {
        let got = self.advance().clone();
        if &got != expected {
            return Err(YaraError::Parse(format!(
                "expected {expected:?}, got {got:?}"
            )));
        }
        Ok(())
    }

    fn parse_file(&mut self) -> crate::yara::Result<Vec<ParsedYaraRule>> {
        let mut rules = Vec::new();

        loop {
            match self.peek() {
                Token::Eof => break,
                Token::Import => self.skip_import()?,
                Token::Rule => rules.push(self.parse_rule()?),
                other => {
                    return Err(YaraError::Parse(format!(
                        "expected 'rule' or 'import', got {other:?}"
                    )));
                }
            }
        }

        Ok(rules)
    }

    fn skip_import(&mut self) -> crate::yara::Result<()> {
        self.advance(); // consume 'import'
        // Skip the import target (a string literal)
        match self.peek() {
            Token::StringLit(_) => {
                self.advance();
            }
            _ => {
                // Skip any token after import
                self.advance();
            }
        }
        Ok(())
    }

    fn parse_rule(&mut self) -> crate::yara::Result<ParsedYaraRule> {
        self.expect(&Token::Rule)?;

        // Rule name
        let name = match self.advance().clone() {
            Token::Ident(name) => name,
            other => {
                return Err(YaraError::Parse(format!(
                    "expected rule name, got {other:?}"
                )));
            }
        };

        // Optional tags: rule Name : tag1 tag2 {
        let mut tags = Vec::new();
        if *self.peek() == Token::Colon {
            self.advance(); // consume :
            while let Token::Ident(_) = self.peek() {
                if let Token::Ident(tag) = self.advance().clone() {
                    tags.push(tag);
                }
            }
        }

        self.expect(&Token::LBrace)?;

        let mut meta = HashMap::new();
        let mut patterns = Vec::new();
        let mut condition = ConditionExpr::Bool(true);

        // Parse sections in any order
        loop {
            match self.peek() {
                Token::RBrace => {
                    self.advance();
                    break;
                }
                Token::Meta => {
                    self.advance(); // consume 'meta'
                    self.expect(&Token::Colon)?;
                    meta = self.parse_meta_section()?;
                }
                Token::Strings => {
                    self.advance(); // consume 'strings'
                    self.expect(&Token::Colon)?;
                    patterns = self.parse_strings_section()?;
                }
                Token::Condition => {
                    self.advance(); // consume 'condition'
                    self.expect(&Token::Colon)?;
                    condition = self.parse_or_expr()?;
                }
                Token::Eof => {
                    return Err(YaraError::Parse(format!("unterminated rule '{name}'")));
                }
                other => {
                    return Err(YaraError::Parse(format!(
                        "unexpected token in rule '{name}': {other:?}"
                    )));
                }
            }
        }

        Ok(ParsedYaraRule {
            name,
            tags,
            meta,
            patterns,
            condition,
        })
    }

    fn parse_meta_section(&mut self) -> crate::yara::Result<HashMap<String, String>> {
        let mut meta = HashMap::new();
        // meta entries are: key = "value" or key = integer
        while let Token::Ident(_) = self.peek() {
            let key = if let Token::Ident(k) = self.advance().clone() {
                k
            } else {
                unreachable!()
            };
            self.expect(&Token::Equals)?;
            let value = match self.advance().clone() {
                Token::StringLit(s) => s,
                Token::IntLit(n) => n.to_string(),
                Token::True => "true".into(),
                Token::False => "false".into(),
                other => {
                    return Err(YaraError::Parse(format!(
                        "expected meta value, got {other:?}"
                    )));
                }
            };
            meta.insert(key, value);
        }
        Ok(meta)
    }

    fn parse_strings_section(&mut self) -> crate::yara::Result<Vec<(String, YaraPattern)>> {
        let mut patterns = Vec::new();

        while let Token::PatternId(_) = self.peek() {
            let id = if let Token::PatternId(id) = self.advance().clone() {
                id
            } else {
                unreachable!()
            };
            self.expect(&Token::Equals)?;

            let pat = match self.advance().clone() {
                Token::StringLit(s) => {
                    let modifiers = self.parse_string_modifiers();
                    self.build_text_pattern(&s, &modifiers)?
                }
                Token::HexBlock(hex) => {
                    if crate::yara::hex_has_wildcards(&hex) {
                        crate::yara::parse_hex_wildcard(&hex)?
                    } else {
                        YaraPattern::Hex(crate::yara::parse_hex(&hex)?)
                    }
                }
                Token::RegexLit(re) => {
                    let modifiers = self.parse_string_modifiers();
                    let re = if modifiers.nocase {
                        format!("(?i){re}")
                    } else {
                        re
                    };
                    YaraPattern::regex(&format!("(?-u){re}"))
                        .map_err(|e| YaraError::InvalidRegex(e.to_string()))?
                }
                other => {
                    return Err(YaraError::Parse(format!(
                        "expected string value for {id}, got {other:?}"
                    )));
                }
            };
            patterns.push((id, pat));
        }
        Ok(patterns)
    }

    fn parse_string_modifiers(&mut self) -> StringModifiers {
        let mut mods = StringModifiers::default();
        loop {
            match self.peek() {
                Token::Nocase => {
                    self.advance();
                    mods.nocase = true;
                }
                Token::Wide => {
                    self.advance();
                    mods.wide = true;
                }
                Token::Ascii => {
                    self.advance();
                    mods.ascii = true;
                }
                Token::Fullword => {
                    self.advance();
                    mods.fullword = true;
                }
                _ => break,
            }
        }
        mods
    }

    fn build_text_pattern(
        &self,
        text: &str,
        modifiers: &StringModifiers,
    ) -> crate::yara::Result<YaraPattern> {
        let bytes = text.as_bytes();

        if modifiers.wide {
            // UTF-16LE encoding: interleave with null bytes
            let mut wide_bytes = Vec::with_capacity(bytes.len() * 2);
            for &b in bytes {
                wide_bytes.push(b);
                wide_bytes.push(0);
            }
            if modifiers.nocase {
                // Build case-insensitive regex from wide bytes
                use std::fmt::Write;
                let mut re = String::from("(?-u)");
                for &b in bytes {
                    if b.is_ascii_alphabetic() {
                        let lo = b.to_ascii_lowercase();
                        let hi = b.to_ascii_uppercase();
                        let _ = write!(re, "[\\x{lo:02x}\\x{hi:02x}]\\x00");
                    } else {
                        let _ = write!(re, "\\x{b:02x}\\x00");
                    }
                }
                return YaraPattern::regex(&re).map_err(|e| YaraError::InvalidRegex(e.to_string()));
            }
            return Ok(YaraPattern::Literal(wide_bytes));
        }

        if modifiers.nocase {
            // Build case-insensitive regex
            use std::fmt::Write;
            let mut re = String::from("(?-u)");
            for &b in bytes {
                if b.is_ascii_alphabetic() {
                    let lo = b.to_ascii_lowercase();
                    let hi = b.to_ascii_uppercase();
                    let _ = write!(re, "[\\x{lo:02x}\\x{hi:02x}]");
                } else {
                    let _ = write!(re, "\\x{b:02x}");
                }
            }
            return YaraPattern::regex(&re).map_err(|e| YaraError::InvalidRegex(e.to_string()));
        }

        Ok(YaraPattern::Literal(bytes.to_vec()))
    }

    // ── Condition expression parser (precedence climbing) ──────────────

    fn parse_or_expr(&mut self) -> crate::yara::Result<ConditionExpr> {
        let mut lhs = self.parse_and_expr()?;
        while *self.peek() == Token::Or {
            self.advance();
            let rhs = self.parse_and_expr()?;
            lhs = ConditionExpr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and_expr(&mut self) -> crate::yara::Result<ConditionExpr> {
        let mut lhs = self.parse_not_expr()?;
        while *self.peek() == Token::And {
            self.advance();
            let rhs = self.parse_not_expr()?;
            lhs = ConditionExpr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not_expr(&mut self) -> crate::yara::Result<ConditionExpr> {
        if *self.peek() == Token::Not {
            self.advance();
            let inner = self.parse_not_expr()?;
            return Ok(ConditionExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> crate::yara::Result<ConditionExpr> {
        match self.peek().clone() {
            Token::True => {
                self.advance();
                Ok(ConditionExpr::Bool(true))
            }
            Token::False => {
                self.advance();
                Ok(ConditionExpr::Bool(false))
            }
            Token::PatternId(name) => {
                let name = name.clone();
                self.advance();
                Ok(ConditionExpr::PatternMatch(name))
            }
            Token::LParen => {
                self.advance();
                let expr = self.parse_or_expr()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }
            Token::Filesize => {
                self.advance();
                let op = self.parse_cmp_op()?;
                let value = self.parse_int_value()?;
                Ok(ConditionExpr::FileSize { op, value })
            }
            // "all of them", "any of them", "N of them"
            // "all of ($a, $b)", "any of ($a, $b)", "N of ($a, $b)"
            Token::All => {
                self.advance();
                self.expect(&Token::Of)?;
                self.parse_of_expr(OfQuantifier::All)
            }
            Token::Any => {
                self.advance();
                self.expect(&Token::Of)?;
                self.parse_of_expr(OfQuantifier::Any)
            }
            Token::IntLit(n) => {
                let n = n as usize;
                self.advance();
                if *self.peek() == Token::Of {
                    self.advance();
                    self.parse_of_expr(OfQuantifier::Count(n))
                } else {
                    Err(YaraError::Parse(format!(
                        "unexpected integer {n} in condition (expected 'N of ...')"
                    )))
                }
            }
            // #name > N — pattern count comparison
            Token::PatternCountId(name) => {
                let name = name.clone();
                self.advance();
                let op = self.parse_cmp_op()?;
                let value = self.parse_int_value()? as usize;
                Ok(ConditionExpr::PatternCount { name, op, value })
            }
            // @name[N] < offset — pattern offset comparison
            Token::PatternOffsetId(name) => {
                let name = name.clone();
                self.advance();
                // Optional index: @a[0] or just @a (defaults to index 0)
                let index = if *self.peek() == Token::LBracket {
                    self.advance(); // [
                    let idx = self.parse_int_value()? as usize;
                    self.expect(&Token::RBracket)?; // ]
                    idx
                } else {
                    0
                };
                let op = self.parse_cmp_op()?;
                let value = self.parse_int_value()?;
                Ok(ConditionExpr::PatternOffset {
                    name,
                    index,
                    op,
                    value,
                })
            }
            // for <quantifier> of <patterns> : ( <constraint> )
            Token::For => {
                self.advance();
                let quantifier = match self.peek().clone() {
                    Token::All => {
                        self.advance();
                        crate::yara::ForQuantifier::All
                    }
                    Token::Any => {
                        self.advance();
                        crate::yara::ForQuantifier::Any
                    }
                    Token::IntLit(n) => {
                        let n = n as usize;
                        self.advance();
                        crate::yara::ForQuantifier::Count(n)
                    }
                    other => {
                        return Err(YaraError::Parse(format!(
                            "expected quantifier after 'for', got {other:?}"
                        )));
                    }
                };

                self.expect(&Token::Of)?;

                let pat_set = match self.peek() {
                    Token::Them => {
                        self.advance();
                        crate::yara::ForPatterns::Them
                    }
                    Token::LParen => {
                        self.advance();
                        let mut names = Vec::new();
                        loop {
                            match self.peek().clone() {
                                Token::PatternId(name) => {
                                    names.push(name.clone());
                                    self.advance();
                                    if *self.peek() == Token::Comma {
                                        self.advance();
                                    }
                                }
                                Token::RParen => {
                                    self.advance();
                                    break;
                                }
                                other => {
                                    return Err(YaraError::Parse(format!(
                                        "expected pattern ID in 'for..of', got {other:?}"
                                    )));
                                }
                            }
                        }
                        crate::yara::ForPatterns::Named(names)
                    }
                    other => {
                        return Err(YaraError::Parse(format!(
                            "expected 'them' or '(' after 'of', got {other:?}"
                        )));
                    }
                };

                self.expect(&Token::Colon)?;
                self.expect(&Token::LParen)?;

                // Parse constraint: $ at <offset> or $ in (<lo>..<hi>)
                // The $ here is a placeholder — we expect PatternId("$")
                match self.peek().clone() {
                    Token::PatternId(ref s) if s == "$" => {
                        self.advance();
                    }
                    _ => {
                        // Some rules may omit the $ — try to parse anyway
                    }
                }

                let constraint = if *self.peek() == Token::At {
                    self.advance();
                    let offset = self.parse_int_value()?;
                    crate::yara::ForConstraint::At(offset)
                } else if *self.peek() == Token::In {
                    self.advance();
                    self.expect(&Token::LParen)?;
                    let lo = self.parse_int_value()?;
                    self.expect(&Token::DotDot)?;
                    let hi = self.parse_int_value()?;
                    self.expect(&Token::RParen)?;
                    crate::yara::ForConstraint::InRange(lo, hi)
                } else {
                    return Err(YaraError::Parse(
                        "expected 'at' or 'in' in for..of constraint".into(),
                    ));
                };

                self.expect(&Token::RParen)?;

                Ok(ConditionExpr::ForOf {
                    quantifier,
                    patterns: pat_set,
                    constraint,
                })
            }
            other => Err(YaraError::Parse(format!(
                "unexpected token in condition: {other:?}"
            ))),
        }
    }

    fn parse_cmp_op(&mut self) -> crate::yara::Result<CmpOp> {
        match self.advance().clone() {
            Token::Lt => Ok(CmpOp::Lt),
            Token::Le => Ok(CmpOp::Le),
            Token::Gt => Ok(CmpOp::Gt),
            Token::Ge => Ok(CmpOp::Ge),
            Token::EqEq => Ok(CmpOp::Eq),
            Token::Ne => Ok(CmpOp::Ne),
            other => Err(YaraError::Parse(format!(
                "expected comparison operator, got {other:?}"
            ))),
        }
    }

    fn parse_int_value(&mut self) -> crate::yara::Result<u64> {
        match self.advance().clone() {
            Token::IntLit(n) => Ok(n),
            other => Err(YaraError::Parse(format!(
                "expected integer value, got {other:?}"
            ))),
        }
    }

    fn parse_of_expr(&mut self, quantifier: OfQuantifier) -> crate::yara::Result<ConditionExpr> {
        match self.peek() {
            Token::Them => {
                self.advance();
                match quantifier {
                    OfQuantifier::All => Ok(ConditionExpr::AllOfThem),
                    OfQuantifier::Any => Ok(ConditionExpr::AnyOfThem),
                    OfQuantifier::Count(n) => Ok(ConditionExpr::NOfThem(n)),
                }
            }
            Token::LParen => {
                self.advance();
                let mut names = Vec::new();
                loop {
                    match self.peek().clone() {
                        Token::PatternId(name) => {
                            names.push(name.clone());
                            self.advance();
                            if *self.peek() == Token::Comma {
                                self.advance();
                            }
                        }
                        Token::RParen => {
                            self.advance();
                            break;
                        }
                        other => {
                            return Err(YaraError::Parse(format!(
                                "expected pattern ID or ')' in 'of' expression, got {other:?}"
                            )));
                        }
                    }
                }
                match quantifier {
                    OfQuantifier::All => Ok(ConditionExpr::AllOf(names)),
                    OfQuantifier::Any => Ok(ConditionExpr::AnyOf(names)),
                    OfQuantifier::Count(n) => Ok(ConditionExpr::NOf(n, names)),
                }
            }
            other => Err(YaraError::Parse(format!(
                "expected 'them' or '(' after 'of', got {other:?}"
            ))),
        }
    }
}

enum OfQuantifier {
    All,
    Any,
    Count(usize),
}

#[derive(Debug, Default)]
struct StringModifiers {
    nocase: bool,
    wide: bool,
    ascii: bool,
    fullword: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a YARA `.yar` file string into a list of parsed rules.
///
/// # Errors
/// Returns `YaraError` if the syntax is invalid.
pub fn parse_yar(input: &str) -> crate::yara::Result<Vec<ParsedYaraRule>> {
    let mut lexer = Lexer::new(input);
    let mut parser = Parser::new(&mut lexer)?;
    parser.parse_file()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Lexer tests ────────────────────────────────────────────────────

    fn tokenize(input: &str) -> Vec<Token> {
        let mut lexer = Lexer::new(input);
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token().unwrap();
            if tok == Token::Eof {
                break;
            }
            tokens.push(tok);
        }
        tokens
    }

    #[test]
    fn lex_keywords() {
        let tokens = tokenize(
            "rule meta strings condition import true false and or not all any of them filesize",
        );
        assert_eq!(
            tokens,
            vec![
                Token::Rule,
                Token::Meta,
                Token::Strings,
                Token::Condition,
                Token::Import,
                Token::True,
                Token::False,
                Token::And,
                Token::Or,
                Token::Not,
                Token::All,
                Token::Any,
                Token::Of,
                Token::Them,
                Token::Filesize,
            ]
        );
    }

    #[test]
    fn lex_pattern_id() {
        let tokens = tokenize("$a $my_pattern $x1");
        assert_eq!(
            tokens,
            vec![
                Token::PatternId("$a".into()),
                Token::PatternId("$my_pattern".into()),
                Token::PatternId("$x1".into()),
            ]
        );
    }

    #[test]
    fn lex_string_literal() {
        let tokens = tokenize(r#""hello world" "with \"escape""#);
        assert_eq!(
            tokens,
            vec![
                Token::StringLit("hello world".into()),
                Token::StringLit("with \"escape".into()),
            ]
        );
    }

    #[test]
    fn lex_hex_block() {
        let tokens = tokenize("{ 4D 5A ?? 00 }");
        assert_eq!(tokens, vec![Token::HexBlock("4D 5A ?? 00".into())]);
    }

    #[test]
    fn lex_regex_literal() {
        let tokens = tokenize(r"/test[0-9]+/");
        assert_eq!(tokens, vec![Token::RegexLit("test[0-9]+".into())]);
    }

    #[test]
    fn lex_integers() {
        let tokens = tokenize("42 1024 1MB 2KB 0xFF");
        assert_eq!(
            tokens,
            vec![
                Token::IntLit(42),
                Token::IntLit(1024),
                Token::IntLit(1_048_576),
                Token::IntLit(2048),
                Token::IntLit(255),
            ]
        );
    }

    #[test]
    fn lex_operators() {
        let tokens = tokenize("< > <= >= == != = : , ( ) { }");
        assert_eq!(
            tokens,
            vec![
                Token::Lt,
                Token::Gt,
                Token::Le,
                Token::Ge,
                Token::EqEq,
                Token::Ne,
                Token::Equals,
                Token::Colon,
                Token::Comma,
                Token::LParen,
                Token::RParen,
                Token::LBrace,
                Token::RBrace,
            ]
        );
    }

    #[test]
    fn lex_single_line_comment() {
        let tokens = tokenize("rule // this is a comment\nmeta");
        assert_eq!(tokens, vec![Token::Rule, Token::Meta]);
    }

    #[test]
    fn lex_multi_line_comment() {
        let tokens = tokenize("rule /* multi\nline */ meta");
        assert_eq!(tokens, vec![Token::Rule, Token::Meta]);
    }

    #[test]
    fn lex_modifiers() {
        let tokens = tokenize("nocase wide ascii fullword");
        assert_eq!(
            tokens,
            vec![Token::Nocase, Token::Wide, Token::Ascii, Token::Fullword]
        );
    }

    #[test]
    fn lex_empty() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   \n\t  ").is_empty());
        assert!(tokenize("// just a comment").is_empty());
    }

    // ── Parser tests ───────────────────────────────────────────────────

    #[test]
    fn parse_minimal_rule() {
        let rules = parse_yar(
            r#"
            rule TestRule {
                condition:
                    true
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "TestRule");
        assert!(rules[0].patterns.is_empty());
        assert!(matches!(rules[0].condition, ConditionExpr::Bool(true)));
    }

    #[test]
    fn parse_rule_with_tags() {
        let rules = parse_yar(
            r#"
            rule Tagged : malware linux {
                condition:
                    true
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules[0].tags, vec!["malware", "linux"]);
    }

    #[test]
    fn parse_meta_section() {
        let rules = parse_yar(
            r#"
            rule WithMeta {
                meta:
                    description = "Test rule"
                    severity = "high"
                    author = "tester"
                    version = 2
                condition:
                    true
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules[0].meta.get("description").unwrap(), "Test rule");
        assert_eq!(rules[0].meta.get("severity").unwrap(), "high");
        assert_eq!(rules[0].meta.get("version").unwrap(), "2");
    }

    #[test]
    fn parse_text_strings() {
        let rules = parse_yar(
            r#"
            rule Strings {
                strings:
                    $a = "hello"
                    $b = "world" nocase
                condition:
                    $a or $b
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules[0].patterns.len(), 2);
        assert_eq!(rules[0].patterns[0].0, "$a");
    }

    #[test]
    fn parse_hex_strings() {
        let rules = parse_yar(
            r#"
            rule HexRule {
                strings:
                    $magic = { 7F 45 4C 46 }
                    $wild = { 4D ?? 5A }
                condition:
                    $magic or $wild
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules[0].patterns.len(), 2);
    }

    #[test]
    fn parse_regex_strings() {
        let rules = parse_yar(
            r#"
            rule RegexRule {
                strings:
                    $re = /UPX[0-9]/
                condition:
                    $re
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules[0].patterns.len(), 1);
    }

    #[test]
    fn parse_condition_and_or() {
        let rules = parse_yar(
            r#"
            rule BoolExpr {
                strings:
                    $a = "AA"
                    $b = "BB"
                    $c = "CC"
                condition:
                    $a and ($b or $c)
            }
            "#,
        )
        .unwrap();
        // Top level should be And
        assert!(matches!(rules[0].condition, ConditionExpr::And(_, _)));
    }

    #[test]
    fn parse_condition_not() {
        let rules = parse_yar(
            r#"
            rule NotExpr {
                strings:
                    $a = "bad"
                condition:
                    not $a
            }
            "#,
        )
        .unwrap();
        assert!(matches!(rules[0].condition, ConditionExpr::Not(_)));
    }

    #[test]
    fn parse_condition_any_of_them() {
        let rules = parse_yar(
            r#"
            rule AnyOfThem {
                strings:
                    $a = "X"
                    $b = "Y"
                condition:
                    any of them
            }
            "#,
        )
        .unwrap();
        assert!(matches!(rules[0].condition, ConditionExpr::AnyOfThem));
    }

    #[test]
    fn parse_condition_all_of_them() {
        let rules = parse_yar(
            r#"
            rule AllOfThem {
                strings:
                    $a = "X"
                    $b = "Y"
                condition:
                    all of them
            }
            "#,
        )
        .unwrap();
        assert!(matches!(rules[0].condition, ConditionExpr::AllOfThem));
    }

    #[test]
    fn parse_condition_n_of_them() {
        let rules = parse_yar(
            r#"
            rule NOfThem {
                strings:
                    $a = "A"
                    $b = "B"
                    $c = "C"
                condition:
                    2 of them
            }
            "#,
        )
        .unwrap();
        assert!(matches!(rules[0].condition, ConditionExpr::NOfThem(2)));
    }

    #[test]
    fn parse_condition_any_of_subset() {
        let rules = parse_yar(
            r#"
            rule AnyOfSubset {
                strings:
                    $a = "A"
                    $b = "B"
                    $c = "C"
                condition:
                    any of ($a, $b)
            }
            "#,
        )
        .unwrap();
        match &rules[0].condition {
            ConditionExpr::AnyOf(names) => {
                assert_eq!(names, &vec!["$a".to_string(), "$b".to_string()]);
            }
            other => panic!("expected AnyOf, got {other:?}"),
        }
    }

    #[test]
    fn parse_condition_filesize() {
        let rules = parse_yar(
            r#"
            rule FileSizeCheck {
                condition:
                    filesize < 1MB
            }
            "#,
        )
        .unwrap();
        match &rules[0].condition {
            ConditionExpr::FileSize { op, value } => {
                assert_eq!(*op, CmpOp::Lt);
                assert_eq!(*value, 1_048_576);
            }
            other => panic!("expected FileSize, got {other:?}"),
        }
    }

    #[test]
    fn parse_condition_filesize_and_pattern() {
        let rules = parse_yar(
            r#"
            rule Combined {
                strings:
                    $a = "test"
                condition:
                    $a and filesize < 10KB
            }
            "#,
        )
        .unwrap();
        assert!(matches!(rules[0].condition, ConditionExpr::And(_, _)));
    }

    #[test]
    fn parse_multiple_rules() {
        let rules = parse_yar(
            r#"
            rule First {
                condition: true
            }
            rule Second {
                condition: false
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "First");
        assert_eq!(rules[1].name, "Second");
    }

    #[test]
    fn parse_import_skipped() {
        let rules = parse_yar(
            r#"
            import "pe"
            import "elf"

            rule AfterImport {
                condition: true
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "AfterImport");
    }

    #[test]
    fn parse_complex_rule() {
        let rules = parse_yar(
            r#"
            rule SuspiciousELF : linux packed {
                meta:
                    description = "Suspicious packed ELF"
                    severity = "high"

                strings:
                    $elf = { 7F 45 4C 46 }
                    $upx0 = "UPX0"
                    $upx1 = "UPX1"
                    $packed = /UPX[0-9]/

                condition:
                    $elf and ($upx0 or $upx1 or $packed) and filesize < 1MB
            }
            "#,
        )
        .unwrap();
        assert_eq!(rules[0].name, "SuspiciousELF");
        assert_eq!(rules[0].tags, vec!["linux", "packed"]);
        assert_eq!(rules[0].meta.get("severity").unwrap(), "high");
        assert_eq!(rules[0].patterns.len(), 4);
        // Condition: $elf and (($upx0 or $upx1) or $packed) and filesize < 1MB
        assert!(matches!(rules[0].condition, ConditionExpr::And(_, _)));
    }

    // ── Error case tests ───────────────────────────────────────────────

    #[test]
    fn parse_error_unterminated_rule() {
        let result = parse_yar("rule Bad {");
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_missing_condition() {
        // Rule with strings but no condition — defaults to true, no error
        let result = parse_yar(
            r#"
            rule NoCondition {
                strings:
                    $a = "test"
            }
            "#,
        );
        // Should succeed with default condition = true
        assert!(result.is_ok());
    }

    #[test]
    fn parse_error_bad_hex() {
        let result = parse_yar(
            r#"
            rule BadHex {
                strings:
                    $a = { ZZ ZZ }
                condition:
                    $a
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_unterminated_string() {
        let mut lexer = Lexer::new(r#""unterminated"#);
        let result = lexer.next_token();
        assert!(result.is_err());
    }

    // ── eval_condition tests ───────────────────────────────────────────

    use crate::yara::eval_condition;

    fn hits(names: &[(&str, bool)]) -> Vec<crate::yara::PatternMatchInfo> {
        names
            .iter()
            .map(|(n, h)| crate::yara::PatternMatchInfo {
                name: n.to_string(),
                matched: *h,
                count: if *h { 1 } else { 0 },
                offsets: Vec::new(),
            })
            .collect()
    }

    #[test]
    fn eval_bool() {
        assert!(eval_condition(&ConditionExpr::Bool(true), &[], 0));
        assert!(!eval_condition(&ConditionExpr::Bool(false), &[], 0));
    }

    #[test]
    fn eval_pattern_match() {
        let h = hits(&[("$a", true), ("$b", false)]);
        assert!(eval_condition(
            &ConditionExpr::PatternMatch("$a".into()),
            &h,
            0
        ));
        assert!(!eval_condition(
            &ConditionExpr::PatternMatch("$b".into()),
            &h,
            0
        ));
        assert!(!eval_condition(
            &ConditionExpr::PatternMatch("$c".into()),
            &h,
            0
        ));
    }

    #[test]
    fn eval_all_any_of_them() {
        let all_hit = hits(&[("$a", true), ("$b", true)]);
        let some_hit = hits(&[("$a", true), ("$b", false)]);

        assert!(eval_condition(&ConditionExpr::AllOfThem, &all_hit, 0));
        assert!(!eval_condition(&ConditionExpr::AllOfThem, &some_hit, 0));
        assert!(eval_condition(&ConditionExpr::AnyOfThem, &some_hit, 0));
    }

    #[test]
    fn eval_n_of_them() {
        let h = hits(&[("$a", true), ("$b", true), ("$c", false)]);
        assert!(eval_condition(&ConditionExpr::NOfThem(2), &h, 0));
        assert!(!eval_condition(&ConditionExpr::NOfThem(3), &h, 0));
    }

    #[test]
    fn eval_filesize() {
        let expr = ConditionExpr::FileSize {
            op: CmpOp::Lt,
            value: 1024,
        };
        assert!(eval_condition(&expr, &[], 512));
        assert!(!eval_condition(&expr, &[], 2048));
    }

    #[test]
    fn eval_and_or_not() {
        let h = hits(&[("$a", true), ("$b", false)]);

        let expr_and = ConditionExpr::And(
            Box::new(ConditionExpr::PatternMatch("$a".into())),
            Box::new(ConditionExpr::PatternMatch("$b".into())),
        );
        assert!(!eval_condition(&expr_and, &h, 0));

        let expr_or = ConditionExpr::Or(
            Box::new(ConditionExpr::PatternMatch("$a".into())),
            Box::new(ConditionExpr::PatternMatch("$b".into())),
        );
        assert!(eval_condition(&expr_or, &h, 0));

        let expr_not = ConditionExpr::Not(Box::new(ConditionExpr::PatternMatch("$b".into())));
        assert!(eval_condition(&expr_not, &h, 0));
    }

    #[test]
    fn eval_of_subset() {
        let h = hits(&[("$a", true), ("$b", false), ("$c", true)]);
        let expr = ConditionExpr::AnyOf(vec!["$a".into(), "$b".into()]);
        assert!(eval_condition(&expr, &h, 0));

        let expr = ConditionExpr::AllOf(vec!["$a".into(), "$c".into()]);
        assert!(eval_condition(&expr, &h, 0));

        let expr = ConditionExpr::AllOf(vec!["$a".into(), "$b".into()]);
        assert!(!eval_condition(&expr, &h, 0));
    }

    // ── Engine integration tests ───────────────────────────────────────

    #[test]
    fn engine_load_yar_and_scan() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule DetectELF {
                strings:
                    $elf = { 7F 45 4C 46 }
                condition:
                    $elf
            }
        "#;
        let count = engine.load_rules_yar(yar).unwrap();
        assert_eq!(count, 1);

        let findings = engine.scan(b"\x7fELF\x02\x01\x01");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "DetectELF");

        assert!(engine.scan(b"not an elf").is_empty());
    }

    #[test]
    fn engine_yar_complex_condition() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule Complex {
                meta:
                    severity = "high"
                strings:
                    $a = "AAAA"
                    $b = "BBBB"
                    $c = "CCCC"
                condition:
                    ($a or $b) and $c and filesize < 1MB
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // Has $a and $c but not $b — should match ($a or $b = true, $c = true)
        let data = b"AAAA some stuff CCCC";
        let findings = engine.scan(data);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, crate::types::FindingSeverity::High);

        // Has only $c — ($a or $b) is false
        assert!(engine.scan(b"CCCC only").is_empty());
    }

    #[test]
    fn engine_yar_and_toml_together() {
        let mut engine = crate::yara::YaraEngine::new();

        // Load a TOML rule
        let toml = r#"
[[rule]]
name = "toml_rule"
severity = "low"
condition = "any"
[[rule.patterns]]
id = "$x"
type = "literal"
value = "TOML"
"#;
        engine.load_rules_toml(toml).unwrap();

        // Load a .yar rule
        let yar = r#"
            rule YarRule {
                strings:
                    $y = "YARA"
                condition:
                    $y
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        assert_eq!(engine.rule_count(), 2);

        let findings = engine.scan(b"has TOML and YARA");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn engine_yar_n_of_them() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule TwoOfThree {
                strings:
                    $a = "AA"
                    $b = "BB"
                    $c = "CC"
                condition:
                    2 of them
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        assert!(engine.scan(b"only AA here").is_empty());
        assert_eq!(engine.scan(b"AA and BB").len(), 1);
        assert_eq!(engine.scan(b"AA BB CC").len(), 1);
    }

    #[test]
    fn engine_yar_filesize_filter() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule SmallFile {
                strings:
                    $a = "X"
                condition:
                    $a and filesize < 100
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        assert_eq!(engine.scan(b"X").len(), 1);
        let big = vec![b'X'; 200];
        assert!(engine.scan(&big).is_empty());
    }

    #[test]
    fn engine_yar_wide_string() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule WideString {
                strings:
                    $w = "AB" wide
                condition:
                    $w
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // "AB" in UTF-16LE = A\0B\0
        assert_eq!(engine.scan(b"A\x00B\x00").len(), 1);
        assert!(engine.scan(b"AB").is_empty());
    }

    #[test]
    fn engine_yar_nocase_string() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule NocaseString {
                strings:
                    $n = "hello" nocase
                condition:
                    $n
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        assert_eq!(engine.scan(b"HELLO").len(), 1);
        assert_eq!(engine.scan(b"HeLLo").len(), 1);
        assert_eq!(engine.scan(b"hello").len(), 1);
        assert!(engine.scan(b"nope").is_empty());
    }

    // ── #count operator tests ──────────────────────────────────────────

    #[test]
    fn parse_condition_pattern_count() {
        let rules = parse_yar(
            r#"
            rule CountRule {
                strings:
                    $a = "AA"
                condition:
                    #a > 2
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            rules[0].condition,
            ConditionExpr::PatternCount { .. }
        ));
    }

    #[test]
    fn engine_yar_pattern_count() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule ThreeOrMore {
                strings:
                    $a = "XX"
                condition:
                    #a >= 3
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // "XX" appears 2 times — should not match
        assert!(engine.scan(b"XX__XX").is_empty());
        // "XX" appears 3 times — should match
        assert_eq!(engine.scan(b"XX__XX__XX").len(), 1);
        // "XX" appears 4 times — should match
        assert_eq!(engine.scan(b"XXXXXXXXXXXX").len(), 1);
    }

    // ── @offset operator tests ─────────────────────────────────────────

    #[test]
    fn parse_condition_pattern_offset() {
        let rules = parse_yar(
            r#"
            rule OffsetRule {
                strings:
                    $a = "MZ"
                condition:
                    @a[0] == 0
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            rules[0].condition,
            ConditionExpr::PatternOffset { .. }
        ));
    }

    #[test]
    fn engine_yar_pattern_offset() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule AtStart {
                strings:
                    $mz = "MZ"
                condition:
                    @mz[0] == 0
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // "MZ" at offset 0 — match
        assert_eq!(engine.scan(b"MZ\x90\x00").len(), 1);
        // "MZ" at offset 2 — no match (@mz[0] == 2, not 0)
        assert!(engine.scan(b"\x00\x00MZ").is_empty());
    }

    #[test]
    fn engine_yar_pattern_offset_no_index() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule AtStartNoIndex {
                strings:
                    $sig = "PK"
                condition:
                    @sig < 4
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        assert_eq!(engine.scan(b"PK\x03\x04").len(), 1);
        assert!(engine.scan(b"\x00\x00\x00\x00\x00PK").is_empty());
    }

    #[test]
    fn engine_yar_count_and_offset_combined() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule Combined {
                strings:
                    $a = "AA"
                condition:
                    #a >= 2 and @a[0] < 5
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // "AA" at offset 0 and 4 — count=2, first offset=0 < 5 — match
        assert_eq!(engine.scan(b"AA__AA").len(), 1);
        // "AA" at offset 10 and 14 — count=2, first offset=10 >= 5 — no match
        assert!(engine.scan(b"__________AA__AA").is_empty());
    }

    // ── for..of positional constraint tests ────────────────────────────

    #[test]
    fn parse_for_any_of_at() {
        let rules = parse_yar(
            r#"
            rule ForAt {
                strings:
                    $a = "MZ"
                    $b = "PE"
                condition:
                    for any of ($a, $b) : ($ at 0)
            }
            "#,
        )
        .unwrap();
        assert!(matches!(rules[0].condition, ConditionExpr::ForOf { .. }));
    }

    #[test]
    fn engine_for_any_at() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule ForAnyAt {
                strings:
                    $a = "AA"
                    $b = "BB"
                condition:
                    for any of ($a, $b) : ($ at 0)
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // $a at offset 0 — match
        assert_eq!(engine.scan(b"AA__BB").len(), 1);
        // $b at offset 0 — match
        assert_eq!(engine.scan(b"BB__AA").len(), 1);
        // Neither at offset 0
        assert!(engine.scan(b"__AABB").is_empty());
    }

    #[test]
    fn engine_for_all_of_them_at() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule ForAllAt {
                strings:
                    $a = "X"
                condition:
                    for all of them : ($ at 0)
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        assert_eq!(engine.scan(b"X__").len(), 1);
        assert!(engine.scan(b"_X_").is_empty());
    }

    #[test]
    fn engine_for_any_in_range() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule ForInRange {
                strings:
                    $a = "SIG"
                condition:
                    for any of them : ($ in (0..16))
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // "SIG" at offset 4 — within 0..16 — match
        assert_eq!(engine.scan(b"____SIG_rest").len(), 1);
        // "SIG" at offset 20 — outside 0..16 — no match
        assert!(engine.scan(b"____________________SIG").is_empty());
    }

    #[test]
    fn engine_for_n_of_at() {
        let mut engine = crate::yara::YaraEngine::new();
        let yar = r#"
            rule For2At {
                strings:
                    $a = "AA"
                    $b = "BB"
                    $c = "CC"
                condition:
                    for 2 of ($a, $b, $c) : ($ in (0..10))
            }
        "#;
        engine.load_rules_yar(yar).unwrap();

        // $a at 0 and $b at 2 — 2 in range — match
        assert_eq!(engine.scan(b"AABB__CC").len(), 1);
        // Only $a in range — 1 < 2 — no match
        assert_eq!(engine.scan(b"AA__________________BBCC").len(), 0);
    }
}
