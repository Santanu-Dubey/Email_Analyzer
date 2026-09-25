import re
from email import policy, message_from_bytes, message_from_string, message_from_file
from email.utils import parseaddr
from bs4 import BeautifulSoup

def extract_domain(email_address: str) -> str:
    """Extract domain in lowercase from an email header or raw address."""
    if not email_address:
        return ""
    # Use parseaddr to handle "Display Name" <user@domain.com>
    _, addr = parseaddr(email_address)
    if not addr:
        addr = email_address
    # Clean brackets, whitespace
    clean = re.sub(r'[<>\s"\']', '', addr)
    if "@" in clean:
        return clean.split("@")[-1].strip().lower()
    return clean.strip().lower()

def extract_display_name(from_header: str) -> str:
    """Extract human-readable display name from From header."""
    if not from_header:
        return ""
    name, _ = parseaddr(from_header)
    return name.strip()

def extract_href_pairs(msg) -> list:
    """Extract all text and href pairs from HTML parts."""
    pairs = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        content = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        content = payload.decode(errors="ignore") if payload else ""
                    if content:
                        soup = BeautifulSoup(content, "html.parser")
                        for a in soup.find_all("a", href=True):
                            pairs.append({
                                "text": a.get_text(strip=True),
                                "href": a["href"].strip()
                            })
        else:
            if msg.get_content_type() == "text/html":
                try:
                    content = msg.get_content()
                except Exception:
                    payload = msg.get_payload(decode=True)
                    content = payload.decode(errors="ignore") if payload else ""
                if content:
                    soup = BeautifulSoup(content, "html.parser")
                    for a in soup.find_all("a", href=True):
                        pairs.append({
                            "text": a.get_text(strip=True),
                            "href": a["href"].strip()
                        })
    except Exception:
        pass
    return pairs

def parse_eml(file_input) -> dict:
    """
    Parse an EML file from a file path, bytes, string, or file-like object.
    Returns a structured dictionary with headers, decoded body, URLs, and HTML links.
    """
    msg = None
    if isinstance(file_input, (bytes, bytearray)):
        msg = message_from_bytes(file_input, policy=policy.default)
    elif isinstance(file_input, str):
        # Check if it's a file path or raw string
        try:
            with open(file_input, "rb") as f:
                msg = message_from_bytes(f.read(), policy=policy.default)
        except (OSError, ValueError):
            msg = message_from_string(file_input, policy=policy.default)
    elif hasattr(file_input, "read"):
        content = file_input.read()
        if isinstance(content, str):
            msg = message_from_string(content, policy=policy.default)
        else:
            msg = message_from_bytes(content, policy=policy.default)
    else:
        raise ValueError(f"Unsupported input type for parse_eml: {type(file_input)}")

    body = ""
    html_content = ""
    plain_content = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                part_content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                part_content = payload.decode(errors="ignore") if payload else ""

            if ctype == "text/plain" and isinstance(part_content, str):
                plain_content += part_content + "\n"
            elif ctype == "text/html" and isinstance(part_content, str):
                html_content += part_content + "\n"
                soup = BeautifulSoup(part_content, "html.parser")
                body += soup.get_text(separator=" ", strip=True) + "\n"
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            content = payload.decode(errors="ignore") if payload else ""

        if ctype == "text/html" and isinstance(content, str):
            html_content = content
            soup = BeautifulSoup(content, "html.parser")
            body = soup.get_text(separator=" ", strip=True)
        elif isinstance(content, str):
            plain_content = content
            body = content

    if not body.strip() and plain_content.strip():
        body = plain_content.strip()

    # URL extraction: both regex over text body and extracted hrefs
    urls_found = set(re.findall(r'https?://[^\s"\'<>]+', body + " " + html_content + " " + plain_content))
    html_links = extract_href_pairs(msg)
    for link in html_links:
        href = link.get("href", "").strip()
        if href.startswith("http://") or href.startswith("https://"):
            urls_found.add(href)

    return {
        "from": msg.get("From", "").strip(),
        "reply_to": msg.get("Reply-To", "").strip(),
        "to": msg.get("To", "").strip(),
        "subject": msg.get("Subject", "").strip(),
        "date": msg.get("Date", "").strip(),
        "auth_results": msg.get("Authentication-Results", "").strip(),
        "received": msg.get_all("Received", []),
        "body": body.strip(),
        "plain_content": plain_content.strip(),
        "html_content": html_content.strip(),
        "urls": sorted(list(urls_found)),
        "html_links": html_links,
        "from_domain": extract_domain(msg.get("From", "")),
        "reply_to_domain": extract_domain(msg.get("Reply-To", "")),
        "display_name": extract_display_name(msg.get("From", ""))
    }
