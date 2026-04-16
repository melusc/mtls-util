from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from subprocess import CompletedProcess, run
from sys import exit, stderr
from textwrap import dedent

cert_out = Path(__file__).parent / "certs"
cert_out.mkdir(exist_ok=True)

root_key_out = cert_out / "rootCA.key"
root_crt_out = cert_out / "rootCA.crt"


def _run_openssl(*args: str | Path, input=b"", env={}) -> CompletedProcess:
    args = tuple(str(p) for p in args)

    print("$ openssl", " ".join(args), file=stderr)

    if input:
        return run(("openssl", *args), check=True, input=input, env=env)

    return run(("openssl", *args), check=True, env=env)


def gen_ca(args: Args):
    confirm_overwrite(root_key_out)

    _run_openssl(
        "genrsa",
        "-aes256",
        "-passout",
        "stdin",
        "-out",
        root_key_out,
        "8192",
        input=f"{args.root_ca_pass}\n".encode(),
    )

    _run_openssl(
        "req",
        "-x509",
        "-new",
        "-key",
        root_key_out,
        "-sha256",
        "-days",
        "3650",
        "-out",
        root_crt_out,
        "-subj",
        "/C=CH/O=lusc.ch/CN=mTLS-Private-Root-CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-passin",
        "stdin",
        input=f"{args.root_ca_pass}\n".encode(),
    )


def gen_client(args: Args):
    key_out = cert_out / f"{args.file_name}.key"
    csr_out = cert_out / f"{args.file_name}.csr"
    crt_out = cert_out / f"{args.file_name}.crt"
    p12_out = cert_out / f"{args.file_name}.p12"

    confirm_overwrite(key_out)

    _run_openssl("genrsa", "-out", key_out, "4096")
    _run_openssl(
        "req",
        "-new",
        "-key",
        key_out,
        "-out",
        csr_out,
        "-subj",
        f"/C=CH/O=lusc.ch/OU={args.device}/CN={args.login}",
    )

    mtls_ext = dedent(f"""
        basicConstraints = critical, CA:FALSE
        keyUsage = critical, digitalSignature
        extendedKeyUsage = critical, clientAuth
    """).strip()

    env = {"CA_PASSWORD": args.root_ca_pass}

    _run_openssl(
        "x509",
        "-req",
        "-in",
        csr_out,
        "-CA",
        root_crt_out,
        "-CAkey",
        root_key_out,
        "-CAcreateserial",
        "-out",
        crt_out,
        "-days",
        "365",
        "-sha256",
        "-extfile",
        "-",
        "-passin",
        "env:CA_PASSWORD",
        input=f"{mtls_ext}\n".encode(),
        env=env,
    )

    _run_openssl(
        "pkcs12",
        "-export",
        "-out",
        p12_out,
        "-inkey",
        key_out,
        "-in",
        crt_out,
        "-certfile",
        root_crt_out,
        "-name",
        f"mTLS-{args.device}-Cert",
        "-keypbe",
        "AES-256-CBC",
        "-certpbe",
        "AES-256-CBC",
        "-macalg",
        "SHA256",
        "-passout",
        "stdin",
        input=f"{args.client_pass}\n".encode(),
    )


def confirm_overwrite(file_name: str | Path):
    if not isinstance(file_name, Path):
        file_name = cert_out / file_name

    if not file_name.exists():
        return

    answer = input(f'"{file_name.name}" already exists. Overwrite? [y/N] ')
    if not answer.startswith(("y", "Y")):
        print("Aborting", file=stderr)
        exit(1)


@dataclass(kw_only=True, frozen=True)
class Args:
    file_name: str
    device: str
    login: str
    gen_ca: bool
    root_ca_pass: str
    client_pass: str


def parse_args() -> Args:
    from argparse import ArgumentParser, BooleanOptionalAction

    parser = ArgumentParser("mtls-util")

    parser.add_argument(
        "-f",
        "--file-name",
        required=True,
        help="Name of files to write to without extension",
    )
    parser.add_argument(
        "-d", "--device", required=True, help="Name of device or similar"
    )
    parser.add_argument("-l", "--login", required=True, help="Your username")
    parser.add_argument(
        "--gen-ca",
        required=False,
        default=False,
        action=BooleanOptionalAction,
        help="Generate new CA",
    )

    args = parser.parse_args()

    ca_pass = getpass("Root CA encryption password: ")
    client_pass = getpass("Client certificate encryption password: ")

    return Args(
        file_name=args.file_name,
        device=args.device,
        login=args.login,
        gen_ca=args.gen_ca,
        root_ca_pass=ca_pass,
        client_pass=client_pass,
    )


def main():
    args = parse_args()

    if args.gen_ca or not root_key_out.exists():
        gen_ca(args)

    gen_client(args)


if __name__ == "__main__":
    main()
