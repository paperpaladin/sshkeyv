// sshkeyv: read OpenSSH keys and certificates, and answer the questions an
// SSH certificate authority deployment raises.
//
// Exit status is part of the contract and the suite asserts on it:
//   0  every requested check passed
//   1  the input is malformed or unreadable
//   2  usage error
//   3  a signature did not verify
//   4  parsed, but not valid now or not authorising the principal asked about

const USAGE: &str = "\
usage: sshkeyv COMMAND [OPTIONS] [FILE...]

  fields          one \"name value\" line per field, tab separated
  check           parse fully; print ok or the refusal
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", USAGE);
        std::process::exit(2);
    }
    eprintln!("sshkeyv: unknown command {}", args[0]);
    std::process::exit(2);
}
