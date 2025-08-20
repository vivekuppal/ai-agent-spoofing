import smtplib
import ssl
import socket
from email.message import EmailMessage
from email.utils import make_msgid, formatdate
from pathlib import Path
from typing import Iterable, Optional, Union


class EmailSender:
    """
    SMTP email sender with:
      - robust error handling
      - context manager + persistent connection for bulk sends
      - optional DKIM signing (dkimpy)
    """

    # Reasonable defaults for DKIM header set
    _DEFAULT_DKIM_HEADERS = [
        "From", "To", "Subject", "Date", "Message-ID",
        "Reply-To", "Cc", "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
    ]

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        *,
        use_tls: bool = True,
        use_ssl: bool = False,
        timeout: float = 30.0,
        client_hostname: Optional[str] = None,
        # --- DKIM options (all optional) ---
        dkim_selector: Optional[str] = None,
        dkim_domain: Optional[str] = None,
        dkim_private_key: Optional[Union[str, bytes]] = None,   # path or PEM bytes
        dkim_headers: Optional[Iterable[str]] = None,
        dkim_identity: Optional[str] = None,  # usually None
    ):
        if use_tls and use_ssl:
            raise ValueError("Choose either STARTTLS (use_tls=True) or SSL (use_ssl=True), not both.")
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.client_hostname = client_hostname

        # Persistent connection holder
        self._server: Optional[smtplib.SMTP] = None

        # DKIM config
        self.dkim_selector = dkim_selector
        self.dkim_domain = dkim_domain
        self._dkim_private_key = dkim_private_key
        self.dkim_headers = list(dkim_headers) if dkim_headers else self._DEFAULT_DKIM_HEADERS
        self.dkim_identity = dkim_identity

    # ---------- Context manager / persistent connection ----------

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.disconnect(self._server)

    def connect(self):
        """Establish and store a persistent connection if not already connected."""
        if self._server is None:
            self._server = self._connect()
        return self

    def is_connected(self) -> bool:
        return self._server is not None

    # ---------- Connection / teardown helpers ----------

    def _connect(self) -> smtplib.SMTP:
        """
        Establish and authenticate an SMTP connection.
        Raises RuntimeError with a helpful message on failure.
        """
        server: Optional[smtplib.SMTP] = None
        try:
            context = ssl.create_default_context()

            if self.use_ssl:
                server = smtplib.SMTP_SSL(
                    self.smtp_host, self.smtp_port, timeout=self.timeout, context=context
                )
            else:
                server = smtplib.SMTP(
                    self.smtp_host, self.smtp_port, timeout=self.timeout, local_hostname=self.client_hostname
                )
                server.ehlo()
                if self.use_tls:
                    server.starttls(context=context)
                    server.ehlo()

            server.login(self.username, self.password)
            return server

        except smtplib.SMTPAuthenticationError as e:
            self.disconnect(server)
            raise RuntimeError(
                "SMTP authentication failed. Verify username/password (or App Password/OAuth) "
                "and provider settings."
            ) from e
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as e:
            self.disconnect(server)
            raise RuntimeError(
                f"SMTP connection failed or server disconnected while connecting to {self.smtp_host}:{self.smtp_port}."
            ) from e
        except (socket.gaierror, socket.timeout, OSError) as e:
            self.disconnect(server)
            raise RuntimeError(
                f"Network error connecting to SMTP server {self.smtp_host}:{self.smtp_port}: {e}"
            ) from e
        except smtplib.SMTPException as e:
            self.disconnect(server)
            raise RuntimeError(f"General SMTP error during connect: {e}") from e
        except Exception as e:
            self.disconnect(server)
            raise RuntimeError(f"Unexpected error during SMTP connect: {e}") from e

    @staticmethod
    def disconnect(server: Optional[smtplib.SMTP]) -> None:
        """
        Graciously log out (QUIT) and close the socket.
        Safe to call with None or already-closed sockets.
        """
        if server is None:
            return
        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass

    # ---------- Message building ----------

    @staticmethod
    def _coerce_recipients(addrs: Optional[Union[str, Iterable[str]]]) -> list[str]:
        if not addrs:
            return []
        if isinstance(addrs, str):
            return [addrs]
        return [a for a in addrs if a]

    @staticmethod
    def _guess_mime(path: Path) -> tuple[str, str]:
        suffix = path.suffix.lower()
        if suffix in {".txt", ".log"}:
            return "text", "plain"
        if suffix in {".htm", ".html"}:
            return "text", "html"
        if suffix in {".jpg", ".jpeg"}:
            return "image", "jpeg"
        if suffix == ".png":
            return "image", "png"
        if suffix == ".gif":
            return "image", "gif"
        if suffix == ".pdf":
            return "application", "pdf"
        if suffix in {".csv"}:
            return "text", "csv"
        if suffix in {".json"}:
            return "application", "json"
        return "application", "octet-stream"

    def _build_message(
        self,
        *,
        from_addr: str,
        to: Union[str, Iterable[str]],
        subject: str,
        text: Optional[str] = None,
        html: Optional[str] = None,
        cc: Optional[Union[str, Iterable[str]]] = None,
        bcc: Optional[Union[str, Iterable[str]]] = None,
        reply_to: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        attachments: Optional[Iterable[Union[str, Path, tuple[str, bytes, str]]]] = None,
        message_id: Optional[str] = None,
    ) -> tuple[EmailMessage, list[str]]:
        to_list = self._coerce_recipients(to)
        cc_list = self._coerce_recipients(cc)
        bcc_list = self._coerce_recipients(bcc)
        if not to_list and not cc_list and not bcc_list:
            raise ValueError("At least one recipient must be provided in to/cc/bcc.")

        msg = EmailMessage()
        msg["From"] = from_addr
        if to_list:
            msg["To"] = ", ".join(to_list)
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = message_id or make_msgid()
        if reply_to:
            msg["Reply-To"] = reply_to
        if headers:
            for k, v in headers.items():
                msg[k] = v

        if html and text:
            msg.set_content(text)
            msg.add_alternative(html, subtype="html")
        elif html:
            msg.add_alternative(html, subtype="html")
        elif text:
            msg.set_content(text)
        else:
            msg.set_content("")

        for att in attachments or []:
            if isinstance(att, (str, Path)):
                p = Path(att)
                maintype, subtype = self._guess_mime(p)
                with open(p, "rb") as f:
                    data = f.read()
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=p.name)
            elif isinstance(att, tuple) and len(att) == 3:
                filename, data, mime = att
                if "/" in mime:
                    maintype, subtype = mime.split("/", 1)
                else:
                    maintype, subtype = "application", mime
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
            else:
                raise TypeError("Attachment must be a path-like or (filename, bytes, mime) tuple.")

        all_rcpts = to_list + cc_list + bcc_list
        return msg, all_rcpts

    # ---------- DKIM helpers ----------

    def _dkim_enabled(self) -> bool:
        return bool(self.dkim_selector and self.dkim_domain and self._dkim_private_key)

    def _dkim_key_bytes(self) -> bytes:
        if isinstance(self._dkim_private_key, bytes):
            return self._dkim_private_key
        if isinstance(self._dkim_private_key, str):
            with open(self._dkim_private_key, "rb") as f:
                return f.read()
        raise RuntimeError("DKIM is enabled but no private key provided (bytes or path).")

    def _add_dkim(self, msg_bytes: bytes) -> bytes:
        """
        Returns: DKIM-Signature header bytes + original msg_bytes
        """
        try:
            import dkim  # type: ignore
        except ImportError as e:
            raise RuntimeError("DKIM requested but 'dkimpy' is not installed. Run: pip install dkimpy") from e

        headers_present = [h for h in self.dkim_headers if f"{h}:" in msg_bytes.decode("utf-8", errors="ignore")]
        if "From" not in (h.title() for h in headers_present):
            headers_present.insert(0, "From")

        sig = dkim.sign(
            message=msg_bytes,
            selector=self.dkim_selector.encode(),
            domain=self.dkim_domain.encode(),
            privkey=self._dkim_key_bytes(),
            canonicalize=(b"relaxed", b"relaxed"),
            include_headers=[h.encode() for h in headers_present],
            identity=self.dkim_identity.encode() if self.dkim_identity else None,
        )
        # Per dkimpy, prepend the returned header to the raw message
        return sig + msg_bytes

    # ---------- Send (supports persistent connection) ----------

    def _ensure_connection(self) -> tuple[smtplib.SMTP, bool]:
        """
        Returns (server, ephemeral):
          - ephemeral=True if we opened a new one for this call.
        """
        if self._server is not None:
            return self._server, False
        return self._connect(), True

    def send(
        self,
        *,
        from_addr: str,
        to: Union[str, Iterable[str]],
        subject: str,
        text: Optional[str] = None,
        html: Optional[str] = None,
        cc: Optional[Union[str, Iterable[str]]] = None,
        bcc: Optional[Union[str, Iterable[str]]] = None,
        reply_to: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        attachments: Optional[Iterable[Union[str, Path, tuple[str, bytes, str]]]] = None,
        message_id: Optional[str] = None,
    ) -> str:
        """
        Sends the message and returns its Message-ID.
        - Reuses persistent connection if available (context manager or prior connect()).
        - Adds DKIM signature if configured.
        """
        server: Optional[smtplib.SMTP] = None
        ephemeral = True
        try:
            msg, rcpts = self._build_message(
                from_addr=from_addr,
                to=to,
                subject=subject,
                text=text,
                html=html,
                cc=cc,
                bcc=bcc,
                reply_to=reply_to,
                headers=headers,
                attachments=attachments,
                message_id=message_id,
            )

            raw = msg.as_bytes()
            if self._dkim_enabled():
                raw = self._add_dkim(raw)

            server, ephemeral = self._ensure_connection()
            # Use raw send to ensure bytes match what DKIM signed
            server.sendmail(from_addr, rcpts, raw)
            return msg["Message-ID"]

        except smtplib.SMTPRecipientsRefused as e:
            raise RuntimeError(f"All recipients were refused by the server: {e.recipients}") from e
        except smtplib.SMTPSenderRefused as e:
            raise RuntimeError(f"Sender address refused: {e.sender} ({e.smtp_code} {e.smtp_error})") from e
        except smtplib.SMTPDataError as e:
            raise RuntimeError(f"SMTP DATA error: {e.smtp_code} {e.smtp_error}") from e
        except smtplib.SMTPServerDisconnected as e:
            # If we were using a persistent connection, try one reconnect + retry
            if not ephemeral:
                try:
                    self.disconnect(self._server)
                finally:
                    self._server = None
                # reconnect & retry once
                server = self._connect()
                self._server = server
                raw_retry = msg.as_bytes()
                if self._dkim_enabled():
                    raw_retry = self._add_dkim(raw_retry)
                server.sendmail(from_addr, rcpts, raw_retry)
                return msg["Message-ID"]
            raise RuntimeError("Server disconnected during send.") from e
        except smtplib.SMTPException as e:
            raise RuntimeError(f"General SMTP error during send: {e}") from e
        except (socket.timeout, OSError) as e:
            raise RuntimeError(f"Network error during send: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error during send: {e}") from e
        finally:
            if ephemeral and server is not None:
                self.disconnect(server)

    # ---------- Bulk helper (optional) ----------

    def send_many(self, messages: Iterable[dict]) -> list[str]:
        """
        Convenience bulk sender.
        Each dict has the same kwargs as `send()`.
        Uses a persistent connection during the batch.
        Returns list of Message-IDs in order.
        """
        results: list[str] = []
        pre_connected = self._server is not None
        try:
            if not pre_connected:
                self._server = self._connect()
            for m in messages:
                results.append(self.send(**m))
            return results
        finally:
            if not pre_connected:
                self.disconnect(self._server)
                self._server = None


# Convenience factories

def gmail_sender(username: str, password: str, **dkim_opts) -> EmailSender:
    return EmailSender("smtp.gmail.com", 587, username, password,
                       use_tls=True, **dkim_opts)


def outlook365_sender(username: str, password: str, **dkim_opts) -> EmailSender:
    return EmailSender("smtp.office365.com", 587, username, password,
                       use_tls=True, **dkim_opts)


# ---------- CLI test runner (single or bulk) ----------

if __name__ == "__main__":
    import getpass

    print("=== EmailSender Test ===")
    try:
        # smtp = input("SMTP server [smtp.gmail.com]: ").strip() or "smtp.gmail.com"
        # port = int(input("SMTP port (587 TLS / 465 SSL) [587]: ").strip() or "587")
        # username = input("Email username: ").strip()
        # password = getpass.getpass("Email password (or App Password): ")

        password = ''
        smtp = 'smtp.dreamhost.com'
        port = 587
        use_ssl = (port == 465)
        use_tls = (port == 587)
        username = 'vivek@lappuai.com'
        print(f"password: {password}")

        use_ssl = (port == 465)
        use_tls = (port == 587)

        # Optional DKIM (press Enter to skip)
        print("\n--- DKIM (optional; press Enter to skip) ---")
        dkim_selector = input("DKIM selector (e.g., 's1') []: ").strip() or None
        dkim_domain = input("DKIM domain (e.g., 'example.com') []: ").strip() or None
        dkim_key_path = input("Path to DKIM private key (PEM) []: ").strip() or None

        sender = EmailSender(
            smtp_host=smtp,
            smtp_port=port,
            username=username,
            password=password,
            use_tls=use_tls,
            use_ssl=use_ssl,
            dkim_selector=dkim_selector,
            dkim_domain=dkim_domain,
            dkim_private_key=dkim_key_path,
        )

        mode = (input("\nBulk mode? [y/N]: ").strip().lower() or "n")
        if mode == "y":
            # Comma-separated recipients; sends same message to each
            recips = [r.strip() for r in input("Recipients (comma-separated): ").split(",") if r.strip()]
            subject = input("Subject [Bulk Test]: ").strip() or "Bulk Test"
            text = input("Text body [Hello from EmailSender bulk test]: ").strip() or "Hello from EmailSender bulk test"

            with sender:  # persistent connection for the whole batch
                ids = []
                for r in recips:
                    ids.append(sender.send(
                        from_addr=username,
                        to=r,
                        subject=subject,
                        text=text,
                        html=f"<p>{text}</p>",
                    ))
            print("Sent:", ", ".join(ids))
        else:
            to_addr = input("Send test email to (default self): ").strip() or username
            msg_id = sender.send(
                from_addr=username,
                to=to_addr,
                subject="Test EmailSender.py",
                text="This is a test email sent using EmailSender.py",
                html="<p>This is a <b>test email</b> sent using EmailSender.py</p>",
            )
            print(f"Email sent successfully! Message-ID: {msg_id}")

    except Exception as e:
        print(f"Failed: {e}")
