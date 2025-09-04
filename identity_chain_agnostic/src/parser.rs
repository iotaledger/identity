// Copyright 2020-2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;

/// The result of a parser application.
pub type ParserResult<'i, T> = Result<(&'i str, T), ParseError<'i>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
  Char(char),
  Regex(String),
  EoI,
  AnyOf(Vec<Expected>),
}

impl Expected {
  pub fn any_of<I>(expected: I) -> Self
  where
    I: IntoIterator<Item = Expected>,
  {
    Self::AnyOf(expected.into_iter().collect())
  }
}

impl Display for Expected {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Expected::EoI => f.write_str("end of input"),
      Expected::Char(c) => write!(f, "character '{c}'"),
      Expected::Regex(regex) => write!(f, "regular expression `{regex}`"),
      Expected::AnyOf(expected) => {
        write!(
          f,
          "any of {}",
          expected.iter().fold(String::new(), |s, exp| format!("{s}, {exp}"))
        )
      }
    }
  }
}

/// Error that may occure when parsing a value from an input string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError<'i> {
  /// The input that was being parsed.
  pub input: Cow<'i, str>,
  /// The type of failure encountered.
  pub kind: ParseErrorKind,
}

impl<'i> ParseError<'i> {
  pub(crate) fn new(input: impl Into<Cow<'i, str>>, kind: ParseErrorKind) -> Self {
    Self {
      input: input.into(),
      kind,
    }
  }

  /// Takes ownership of the input string.
  pub fn into_owned(self) -> ParseError<'static> {
    let Self { input, kind } = self;
    ParseError::new(Cow::Owned(input.into_owned()), kind)
  }
}

impl<'i> Display for ParseError<'i> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // Show at most 10 characters from input..
    let input_view = &self.input[..usize::min(10, self.input.len())];
    write!(f, "failed to parse \"{input_view}")?;
    if input_view.len() < self.input.len() {
      f.write_str("...")?;
    }
    write!(f, "\": {}", self.kind)
  }
}

impl<'i> std::error::Error for ParseError<'i> {}

/// Possible failure of a parsing operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParseErrorKind {
  /// Encountered an unexpected character.
  UnexpectedCharacter { invalid: char, expected: Option<Expected> },
  /// End of Input.
  EoI,
}

impl Display for ParseErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::EoI => f.write_str("unexpected end of input"),
      Self::UnexpectedCharacter { invalid, expected } => {
        // Show at most 10 characters.
        write!(f, "unexpected character '{invalid}'")?;
        if let Some(expected) = expected.as_ref() {
          write!(f, ", expected {expected}")?;
        }

        Ok(())
      }
    }
  }
}

/// A types that parses the given input into a certain output.
pub trait Parser<'i> {
  /// The type of the parsed output.
  type Output;

  /// Runs this parser against the given input.
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output>;
  /// Maps the output of this parser with the given function.
  fn map<F>(self, f: F) -> Map<Self, F>
  where
    Self: Sized,
  {
    Map { parser: self, f }
  }
}

impl<'i, F, T> Parser<'i> for F
where
  F: FnMut(&'i str) -> ParserResult<'i, T>,
{
  type Output = T;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    self(input)
  }
}

/// A [Parser] that maps its parsing output with a function.
#[derive(Debug)]
pub struct Map<P, F> {
  parser: P,
  f: F,
}

impl<'i, P, F, T> Parser<'i> for Map<P, F>
where
  P: Parser<'i>,
  F: Fn(P::Output) -> T,
{
  type Output = T;

  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    self.parser.process(input).map(|(rem, output)| (rem, (self.f)(output)))
  }
}

#[derive(Debug)]
struct CharParser(char);

impl<'i> Parser<'i> for CharParser {
  type Output = char;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    match input.chars().next() {
      Some(c) if c == self.0 => Ok((&input[1..], c)),
      Some(c) => Err(ParseErrorKind::UnexpectedCharacter {
        invalid: c,
        expected: Some(Expected::Char(self.0)),
      }),
      None => Err(ParseErrorKind::EoI),
    }
    .map_err(|kind| ParseError::new(input, kind))
  }
}

/// A parser that consume exactly one character `c` out of input.
pub fn char<'i>(c: char) -> impl FnMut(&'i str) -> ParserResult<'i, char> {
  let mut parser = CharParser(c);
  move |input| parser.process(input)
}

struct Tag<T>(T);

impl<'i, T: AsRef<str>> Parser<'i> for Tag<T> {
  type Output = &'i str;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    let tag = self.0.as_ref();

    if input.len() < tag.len() {
      let min_len = tag.len() - input.len();
      return Err(ParseError::new(&input[..min_len], ParseErrorKind::EoI));
    }

    for (i, (expected, other)) in tag.chars().zip(input.chars()).enumerate() {
      if expected != other {
        return Err(ParseError::new(
          &input[i..],
          ParseErrorKind::UnexpectedCharacter {
            invalid: other,
            expected: Some(Expected::Char(expected)),
          },
        ));
      }
    }

    let (tag, rem) = input.split_at(tag.len());
    Ok((rem, tag))
  }
}

/// Parses the exact input string `tag`.
pub fn tag<'i, T: AsRef<str>>(tag: T) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str> {
  let mut tag = Tag(tag);
  move |input| tag.process(input)
}

#[derive(Debug)]
struct TakeWhileMinMax<F> {
  min: usize,
  max: usize,
  pred: F,
}

impl<'i, F> Parser<'i> for TakeWhileMinMax<F>
where
  F: Fn(char) -> bool,
{
  type Output = &'i str;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    if input.len() < self.min {
      return Err(ParseError::new(input, ParseErrorKind::EoI));
    }

    let consumed = input
      .char_indices()
      .take_while(|(i, c)| *i < self.max && (self.pred)(*c))
      .count();
    if consumed < self.min {
      return Err(ParseError::new(
        &input[consumed..],
        ParseErrorKind::UnexpectedCharacter {
          invalid: input.chars().nth(consumed).unwrap(),
          expected: None,
        },
      ));
    }

    let (output, rem) = input.split_at(consumed);
    Ok((rem, output))
  }
}

pub fn take_while_min_max<'i, F>(min: usize, max: usize, pred: F) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str>
where
  F: Fn(char) -> bool,
{
  let mut parser = TakeWhileMinMax { min, max, pred };
  move |input| parser.process(input)
}

macro_rules! impl_parser_for_tuple {
    ($($parser:ident $output:ident),+) => {
      impl<'i, $($parser, $output),+> Parser<'i> for ($($parser),+)
      where
        $($parser: Parser<'i, Output = $output>),+
      {
        type Output = ($($output),+);
        #[allow(non_snake_case)]
        fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
          let ($(ref mut $parser),+) = *self;
          $(let (input, $output) = $parser.process(input)?;)+
          Ok((input, ($($output),+)))
        }
      }
    };
}

impl_parser_for_tuple!(P1 O1, P2 O2);
impl_parser_for_tuple!(P1 O1, P2 O2, P3 O3);

#[derive(Debug)]
pub struct Any<PS> {
  parsers: PS,
}

impl<'i, P1, P2, O> Parser<'i> for Any<(P1, P2)>
where
  P1: Parser<'i, Output = O>,
  P2: Parser<'i, Output = O>,
{
  type Output = O;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    self.parsers.0.process(input).or_else(|_| self.parsers.1.process(input))
  }
}

impl<'i, P1, P2, P3, O> Parser<'i> for Any<(P1, P2, P3)>
where
  P1: Parser<'i, Output = O>,
  P2: Parser<'i, Output = O>,
  P3: Parser<'i, Output = O>,
{
  type Output = O;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    self
      .parsers
      .0
      .process(input)
      .or_else(|_| self.parsers.1.process(input))
      .or_else(|_| self.parsers.2.process(input))
  }
}

impl<'i, P1, P2, P3, P4, O> Parser<'i> for Any<(P1, P2, P3, P4)>
where
  P1: Parser<'i, Output = O>,
  P2: Parser<'i, Output = O>,
  P3: Parser<'i, Output = O>,
  P4: Parser<'i, Output = O>,
{
  type Output = O;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    self
      .parsers
      .0
      .process(input)
      .or_else(|_| self.parsers.1.process(input))
      .or_else(|_| self.parsers.2.process(input))
      .or_else(|_| self.parsers.3.process(input))
  }
}

pub fn any<PS>(parsers: PS) -> Any<PS> {
  Any { parsers }
}

#[derive(Debug)]
struct Many1<P> {
  parser: P,
}

impl<'i, P> Parser<'i> for Many1<P>
where
  P: Parser<'i>,
{
  type Output = Vec<P::Output>;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    // Parser must process some input at least once. Error out otherwise.
    let (mut rem, first_output) = self.parser.process(input)?;
    let mut outputs = vec![first_output];

    loop {
      let Ok((r, output)) = self.parser.process(rem) else {
        break;
      };
      rem = r;
      outputs.push(output);
    }

    Ok((rem, outputs))
  }
}

/// Repeatedly applies the given parser and returns the collected outputs.
pub fn many1<'i, P>(parser: P) -> impl FnMut(&'i str) -> ParserResult<'i, Vec<P::Output>>
where
  P: Parser<'i>,
{
  let mut parser = Many1 { parser };
  move |input| parser.process(input)
}

#[derive(Debug)]
struct Recognize<P> {
  parser: P,
}

impl<'i, P> Parser<'i> for Recognize<P>
where
  P: Parser<'i>,
{
  type Output = &'i str;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    let (rem, _) = self.parser.process(input)?;
    let diff = input.len() - rem.len();

    Ok((rem, &input[..diff]))
  }
}

/// Applies the given parser and discards its output, returning the consumed input instead.
pub fn recognize<'i, P>(parser: P) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str>
where
  P: Parser<'i>,
{
  let mut recognize = Recognize { parser };
  move |input| recognize.process(input)
}

/// Applies the given parser and fails if all the input isn't consumed.
pub fn all_consuming<'i, P>(mut parser: P) -> impl FnMut(&'i str) -> ParserResult<'i, P::Output>
where
  P: Parser<'i>,
{
  move |input| {
    let (rem, output) = parser.process(input)?;
    if rem.is_empty() {
      Ok((rem, output))
    } else {
      Err(ParseError::new(
        rem,
        ParseErrorKind::UnexpectedCharacter {
          invalid: rem.chars().next().unwrap(),
          expected: Some(Expected::EoI),
        },
      ))
    }
  }
}

/// Parses a value from the parser `left`, then matches a value from parser `separator` and discards it,
/// then parses another value from parser `right`, returning the two parsed values a couple.
pub fn separated_pair<'i, L, S, R>(
  mut left: L,
  mut separator: S,
  mut right: R,
) -> impl FnMut(&'i str) -> ParserResult<'i, (L::Output, R::Output)>
where
  L: Parser<'i>,
  S: Parser<'i>,
  R: Parser<'i>,
{
  move |input| {
    let (rem, left) = left.process(input)?;
    let (rem, _sep) = separator.process(rem)?;
    let (rem, right) = right.process(rem)?;

    Ok((rem, (left, right)))
  }
}

pub(crate) fn perc_encoded_parser(input: &str) -> ParserResult<'_, u8> {
  let (rem, _perc) = char('%')(input)?;
  take_while_min_max(2, 2, |c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    .map(|hex| u8::from_str_radix(hex, 16).unwrap())
    .process(rem)
}

pub fn is_lowercase_hex_char(c: char) -> bool {
  c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
}

/// Applies parser `prefix` discarding its output, and then applies `parser`.
pub fn preceded<'i, P, T>(prefix: P, parser: T) -> impl FnMut(&'i str) -> ParserResult<'i, T::Output>
where
  P: Parser<'i>,
  T: Parser<'i>,
{
  let mut parser = (prefix, parser).map(|(_, output)| output);
  move |input| parser.process(input)
}

/// Applies the first parser than applies `terminator` discarding its result. Returns the output of the first parser.
pub fn terminated<'i, P, T>(parser: P, terminator: T) -> impl FnMut(&'i str) -> ParserResult<'i, P::Output>
where
  P: Parser<'i>,
  T: Parser<'i>,
{
  let mut parser = (parser, terminator);
  move |input| parser.process(input).map(|(rem, (output, _))| (rem, output))
}

/// Returns `None` instead of an error when the given parser fails.
pub fn opt<'i, P>(parser: P) -> impl FnMut(&'i str) -> ParserResult<'i, Option<P::Output>>
where
  P: Parser<'i>,
{
  let mut parser = parser.map(Some);
  move |input| match parser.process(input) {
    Ok(res) => Ok(res),
    _ => Ok((input, None)),
  }
}

/// Fills the given buffer by repeatedly applying the supplied parser.
pub fn fill<'i, P>(mut parser: P, buf: &mut [P::Output]) -> impl FnMut(&'i str) -> ParserResult<'i, ()> + use<'i, '_, P>
where
  P: Parser<'i>,
{
  move |mut input| {
    for v in buf.iter_mut() {
      let (rem, output) = parser.process(input)?;
      input = rem;
      *v = output;
    }

    Ok((input, ()))
  }
}

/// Parses a single lowercase hex encoded byte.
pub fn lowercase_hex_digit<'i>(input: &'i str) -> ParserResult<'i, u8> {
  take_while_min_max(2, 2, is_lowercase_hex_char)
    .map(|hex_byte| u8::from_str_radix(hex_byte, 16).unwrap())
    .process(input)
}

#[derive(Debug)]
pub struct IteratorParser<'i, P> {
  input: &'i str,
  parser: P,
  failure: Option<ParseError<'i>>,
}

impl<'i, P> Iterator for IteratorParser<'i, P>
where
  P: Parser<'i>,
{
  type Item = P::Output;
  fn next(&mut self) -> Option<Self::Item> {
    if self.failure.is_some() {
      return None;
    }

    match self.parser.process(self.input) {
      Ok((rem, output)) => {
        self.input = rem;
        Some(output)
      }
      Err(e) => {
        self.failure = Some(e);
        None
      }
    }
  }
}

impl<'i, P> IteratorParser<'i, P> {
  fn new(input: &'i str, parser: P) -> Self {
    Self {
      input,
      parser,
      failure: None,
    }
  }

  /// Returns the unconsumed input.
  pub fn remaining_input(&self) -> &'i str {
    self.input
  }

  /// Consumes this iterator returning the parser's error, if any.
  pub fn into_failure(self) -> Option<ParseError<'i>> {
    self.failure
  }
}

pub fn iterator<'i, P>(input: &'i str, parser: P) -> IteratorParser<'i, P>
where
  P: Parser<'i>,
{
  IteratorParser::new(input, parser)
}

/// Matches any character from the given string.
pub fn any_of<'i>(valid_chars: &str) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str> + use<'i, '_> {
  take_while_min_max(1, 1, |c| valid_chars.contains(c))
}

/// Matches 1 or more ASCII alphabetic characters.
pub fn alpha1<'i>(input: &'i str) -> ParserResult<'i, &'i str> {
  take_while_min_max(1, usize::MAX, |c| c.is_ascii_alphabetic())(input)
}

/// Matches 1 or more ASCII digits.
pub fn digit1<'i>(input: &'i str) -> ParserResult<'i, &'i str> {
  take_while_min_max(1, usize::MAX, |c| c.is_ascii_digit())(input)
}

/// Matches one or more ASCII alphanumeric characters.
pub fn alphanumeric1<'i>(input: &'i str) -> ParserResult<'i, &'i str> {
  let mut iter = iterator(input, any((alpha1, digit1)));
  // Parser iterator must yield at least one result.
  let Some(_) = iter.next() else {
    let mut e = iter.into_failure().expect("parser failed");
    if let ParseErrorKind::UnexpectedCharacter {
      invalid,
      expected: None,
    } = e.kind
    {
      e.kind = ParseErrorKind::UnexpectedCharacter {
        invalid,
        expected: Some(Expected::Regex("[0-9A-Za-z]+".to_owned())),
      };
    }
    return Err(e);
  };

  // Exhaust the iterator.
  for _ in iter.by_ref() {}

  let rem = iter.remaining_input();
  let consumed = input.len() - rem.len();

  Ok((rem, &input[..consumed]))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_char() {
    let e = char('@')("").unwrap_err();
    assert_eq!(e, ParseError::new("", ParseErrorKind::EoI));

    let e = char('@')("!!").unwrap_err();
    assert_eq!(
      e,
      ParseError::new(
        "!!",
        ParseErrorKind::UnexpectedCharacter {
          invalid: '!',
          expected: Some(Expected::Char('@'))
        }
      )
    );

    let (rem, x) = char('@')("@..").unwrap();
    assert_eq!(rem, "..");
    assert_eq!(x, '@');
  }

  #[test]
  fn test_take_while_min_max() {
    let e = take_while_min_max(3, 8, |c| c.is_ascii_alphabetic())("").unwrap_err();
    assert_eq!(e.kind, ParseErrorKind::EoI);
    let e = take_while_min_max(3, 8, |c| c.is_ascii_alphabetic())("ab").unwrap_err();
    assert_eq!(e.kind, ParseErrorKind::EoI);
    let e = take_while_min_max(3, 8, |c| c.is_ascii_alphabetic())("ab321abcd3").unwrap_err();
    assert_eq!(
      e,
      ParseError::new(
        "321abcd3",
        ParseErrorKind::UnexpectedCharacter {
          invalid: '3',
          expected: None
        }
      )
    );

    let (rem, x) = take_while_min_max(3, 8, |c| c.is_ascii_alphabetic())("abcdefgh").unwrap();
    assert_eq!(rem, "");
    assert_eq!(x, "abcdefgh");
    let (rem, x) = take_while_min_max(3, 8, |c| c.is_ascii_alphabetic())("abcdefghijkl").unwrap();
    assert_eq!(rem, "ijkl");
    assert_eq!(x, "abcdefgh");
  }

  #[test]
  fn test_any() {
    let at_or_bang = any((char('@'), char('!')));
    let (rem, output) = many1(at_or_bang).process("!!!@@!..").unwrap();
    assert_eq!(rem, "..");
    assert_eq!(output, "!!!@@!".chars().collect::<Vec<_>>());
  }

  #[test]
  fn test_many1() {
    let e = many1(tag("abc"))("bcd").unwrap_err();
    assert_eq!(
      e,
      ParseError::new(
        "bcd",
        ParseErrorKind::UnexpectedCharacter {
          invalid: 'b',
          expected: Some(Expected::Char('a'))
        }
      )
    );

    let (rem, output) = many1(tag("abc"))("abcabcabcdef").unwrap();
    assert_eq!(rem, "def");
    assert_eq!(output, ["abc"; 3].to_vec());
  }

  #[test]
  fn test_recognize() {
    assert_eq!(
      recognize(char('@'))("123").unwrap_err().kind,
      ParseErrorKind::UnexpectedCharacter {
        invalid: '1',
        expected: Some(Expected::Char('@'))
      }
    );

    let (rem, output) = recognize(many1(tag("abc"))).process("abcabcabcdef").unwrap();
    assert_eq!(rem, "def");
    assert_eq!(output, "abcabcabc");
  }

  #[test]
  fn test_all_consuming() {
    let alpha0 = take_while_min_max(0, usize::MAX, |c| c.is_ascii_alphabetic());
    let digit0 = take_while_min_max(0, usize::MAX, |c| c.is_ascii_digit() && !c.is_ascii_alphabetic());
    assert!(all_consuming(alpha0).process("abcdef").is_ok());
    let e = all_consuming(digit0).process("12345abcd").unwrap_err();
    assert_eq!(
      e,
      ParseError::new(
        "abcd",
        ParseErrorKind::UnexpectedCharacter {
          invalid: 'a',
          expected: Some(Expected::EoI)
        }
      )
    )
  }

  #[test]
  fn test_separated_pair() {
    let alpha0 = take_while_min_max(0, usize::MAX, |c| c.is_ascii_alphabetic());
    let mut parser = separated_pair(alpha0, tag(": "), char('@'));
    let (rem, (left, right)) = parser.process("abcdef: @..").unwrap();
    assert_eq!(rem, "..");
    assert_eq!(left, "abcdef");
    assert_eq!(right, '@');
  }

  #[test]
  fn test_map() {
    let (rem, output) = tag("ciao").map(str::len).process("ciaooooo").unwrap();
    assert_eq!(rem, "oooo");
    assert_eq!(output, 4);
  }

  #[test]
  fn test_alphanumeric1() {
    assert_eq!(alphanumeric1("abcdefg12345"), Ok(("", "abcdefg12345")));
    assert_eq!(
      alphanumeric1("!@#%").unwrap_err(),
      ParseError::new(
        "!@#%",
        ParseErrorKind::UnexpectedCharacter {
          invalid: '!',
          expected: Some(Expected::Regex("[0-9A-Za-z]+".to_owned()))
        }
      )
    )
  }
}
