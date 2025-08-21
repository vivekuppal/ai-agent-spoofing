# emailsender.py
# A robust SMTP email sender with optional DKIM signing and persistent
# connection support.
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
      - Jinja2 HTML template rendering (file path or raw template string)
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
                    self.smtp_host, self.smtp_port, timeout=self.timeout,
                    context=context
                )
            else:
                server = smtplib.SMTP(
                    self.smtp_host, self.smtp_port, timeout=self.timeout,
                    local_hostname=self.client_hostname
                )
                server.ehlo()
                if self.use_tls:
                    server.starttls(context=context)
                    server.ehlo()
            print(f"Connecting to SMTP server {self.smtp_host}:{self.smtp_port}")
            print(f"Using TLS: {self.use_tls}, SSL: {self.use_ssl}")
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
        if suffix in {".xml"}:
            return "application", "xml"
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
                msg.add_attachment(data, maintype=maintype, subtype=subtype,
                                   filename=p.name)
            elif isinstance(att, tuple) and len(att) == 3:
                filename, data, mime = att
                if "/" in mime:
                    maintype, subtype = mime.split("/", 1)
                else:
                    maintype, subtype = "application", mime
                msg.add_attachment(data, maintype=maintype, subtype=subtype,
                                   filename=filename)
            else:
                raise TypeError("Attachment must be a path-like or (filename, bytes, mime) tuple.")

        all_rcpts = to_list + cc_list + bcc_list
        return msg, all_rcpts

    # ---------- Jinja2 helpers (HTML template rendering) ----------

    def _render_jinja(
        self,
        *,
        template_str: Optional[str] = None,
        template_path: Optional[Union[str, Path]] = None,
        variables: Optional[dict] = None,
    ) -> str:
        """
        Render a Jinja2 template (string or file path) with auto-escaping for HTML.
        Precedence: template_path > template_str.
        """
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
        except Exception as e:
            raise RuntimeError(
                "HTML template rendering requires Jinja2. Install with: pip install jinja2"
            ) from e

        variables = variables or {}

        if template_path:
            p = Path(template_path)
            if not p.exists():
                raise FileNotFoundError(f"HTML template file not found: {p}")
            env = Environment(
                loader=FileSystemLoader(str(p.parent)),
                autoescape=select_autoescape(["html", "xml"]),
                enable_async=False,
            )
            tmpl = env.get_template(p.name)
            return tmpl.render(**variables)

        if template_str:
            env = Environment(
                autoescape=select_autoescape(["html", "xml"]),
                enable_async=False,
            )
            tmpl = env.from_string(template_str)
            return tmpl.render(**variables)

        raise ValueError("No template provided for rendering (template_path or template_str required).")

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
        # --- NEW: templating inputs ---
        html_template: Optional[str] = None,                 # raw Jinja2 template string
        html_template_path: Optional[Union[str, Path]] = None,  # path to Jinja2 template file
        template_vars: Optional[dict] = None,                # variables for the Jinja2 template
    ) -> str:
        """
        Sends the message and returns its Message-ID.
        - Reuses persistent connection if available (context manager or prior connect()).
        - Adds DKIM signature if configured.
        - HTML rendering precedence:
            explicit `html` > `html_template_path` > `html_template`
        """
        server: Optional[smtplib.SMTP] = None
        ephemeral = True
        try:
            print("Sending email...")
            # --- NEW: compute HTML from template if provided and `html` not explicitly passed ---
            if html is None and (html_template_path or html_template):
                html = self._render_jinja(
                    template_path=html_template_path,
                    template_str=html_template if not html_template_path else None,
                    variables=template_vars or {},
                )

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
    # import getpass

    print("=== EmailSender Test ===")
    try:
        password = ''
        smtp = 'smtp.dreamhost.com'
        port = 587
        use_ssl = (port == 465)
        use_tls = (port == 587)
        username = 'webapp@lappuai.com'

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

            # --- DEMO: render from template file if present, otherwise fallback to raw HTML ---
            tpl_path = input("Path to HTML template (Enter to skip): ").strip() or None
            if tpl_path:
                msg_id = sender.send(
                    from_addr=username,
                    to=to_addr,
                    subject="Test EmailSender.py (Jinja2 Template)",
                    html_template_path=tpl_path,
                    template_vars={"name": "Analyst", "alert_id": "ALRT-12345"},
                )
            else:
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

# Example of persistent connection usage
# with EmailSender("smtp.dreamhost.com", 587, "you@domain.com", "APP_PASSWORD",
#                  use_tls=True) as s:
#     for r in ["a@x.com", "b@x.com", "c@x.com"]:
#         s.send(from_addr="you@domain.com", to=r, subject="Hi", text="Hello!")

# Example of DKIM signing
# s = EmailSender(
#     "smtp.example.com", 587, "you@example.com", "password", use_tls=True,
#     dkim_selector="s1",
#     dkim_domain="example.com",
#     dkim_private_key="/path/to/private_key.pem",  # or PEM bytes
# )
# s.send(from_addr="you@example.com", to="alice@example.com", subject="Signed",
#        text="Hi")


# Message marked as spam by mail channels
# EmailAction: sent <175581259673.4988.17970016430144852112@work-mobile.mynetworksettings.com> emails to ['vivek.uppal@gmail.com', 'vivek@lappuai.com']
