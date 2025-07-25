use std::borrow::Cow;
use std::fmt::Display;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError<'i> {
  pub input: Cow<'i, str>,
  pub kind: ParseErrorKind,
}

impl<'i> ParseError<'i> {
  pub fn new(input: impl Into<Cow<'i, str>>, kind: ParseErrorKind) -> Self {
    Self {
      input: input.into(),
      kind,
    }
  }

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParseErrorKind {
  UnexpectedCharacter { invalid: char, expected: Option<Expected> },
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

pub trait Parser<'i> {
  type Output;

  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output>;
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

pub fn tag<'i, T: AsRef<str>>(tag: T) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str> {
  let mut tag = Tag(tag);
  move |input| tag.process(input)
}

#[derive(Debug)]
struct TakeWhile<F> {
  pred: F,
}

impl<'i, F> Parser<'i> for TakeWhile<F>
where
  F: Fn(char) -> bool,
{
  type Output = &'i str;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    let consumed = input.chars().take_while(|c| (self.pred)(*c)).count();

    let (parsed, rem) = input.split_at(consumed);
    Ok((rem, parsed))
  }
}

pub fn take_while<'i, F>(pred: F) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str>
where
  F: Fn(char) -> bool,
{
  let mut take_while = TakeWhile { pred };
  move |input| take_while.process(input)
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

#[derive(Debug)]
struct Take(usize);

impl<'i> Parser<'i> for Take {
  type Output = &'i str;
  fn process(&mut self, input: &'i str) -> ParserResult<'i, Self::Output> {
    if input.len() < self.0 {
      Err(ParseError::new(input, ParseErrorKind::EoI))
    } else {
      let (output, rem) = input.split_at(self.0);
      Ok((rem, output))
    }
  }
}

pub fn take<'i>(amount: usize) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str> {
  move |input| Take(amount).process(input)
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

pub fn recognize<'i, P>(parser: P) -> impl FnMut(&'i str) -> ParserResult<'i, &'i str>
where
  P: Parser<'i>,
{
  let mut recognize = Recognize { parser };
  move |input| recognize.process(input)
}

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
  fn test_take_while() {
    let mut alpha0 = take_while(|c| c.is_ascii_alphabetic());
    assert_eq!(alpha0("").unwrap(), ("", ""));

    let (rem, output) = alpha0("abcdef1234").unwrap();
    assert_eq!(rem, "1234");
    assert_eq!(output, "abcdef");
  }

  #[test]
  fn test_all_consuming() {
    let alpha0 = take_while(|c| c.is_ascii_alphabetic());
    let digit0 = take_while(|c| c.is_digit(10));
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
}
