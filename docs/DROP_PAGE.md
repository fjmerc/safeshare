# No-JavaScript Drop Page

SafeShare's normal upload page encrypts files in the visitor's browser, which means trusting the JavaScript the server sends. Some senders can't or won't run it: Tor Browser on its **Safest** setting turns JavaScript off, and a source facing a capable adversary may not want to trust any code from the server.

The drop page, at `/drop`, is a plain HTML form for them. It works with JavaScript off. The server encrypts what arrives to a public key you choose, using [age](https://age-encryption.org), and stores only the encrypted result. Only whoever holds the matching private key can open it. The private key never touches the server.

The idea comes from [SecureDrop](https://securedrop.org), which works the same way.

## How it works

1. The sender opens `/drop`, picks a file, can write a message, and submits the form.
2. The server keeps the upload in memory, not on disk. It runs the virus scan if one is configured, and removes identifying metadata from the file (see [What gets cleaned](#what-gets-cleaned)). If cleaning fails for a type it knows how to clean, nothing is stored and the sender is told why.
3. The server packs the file (under its original name) and the message (as `message.txt`) into a tar archive. It pads the archive with zero bytes so that its size only shows a rough bucket, as browser uploads do. It encrypts the archive to `DROP_RECIPIENT` and stores that as `safeshare-drop.tar.age`.
4. The sender gets a code and a link on the result page. They give the code to the recipient however they agreed to.
5. The recipient downloads the file with the code and decrypts it on their own computer with their private key (see [Receiving](#receiving)).

## What it protects against, and what it doesn't

Read this before offering the page to anyone.

**It protects against:**

- **Anyone who gets the stored files later**: a seizure of the server or its disks, a backup that leaks, an operator asked to hand over files after the fact. What is stored is age ciphertext. Without the private key, which isn't on the server, it can't be read.
- **Someone who only has the code.** The code downloads the encrypted file, nothing more.
- **Having to run the server's code.** The sender's browser runs no script, so a malicious script can't be slipped into the page.

**It does not protect against:**

- **A server that is compromised while the sender uploads.** The browser sends the file unencrypted (inside the HTTPS or Tor connection), so the server process holds it in plain form for the moment it takes to clean and encrypt it. Someone who controls the server at that moment can read it, keep a copy, or change the page so that files go to their own key. This is the trade-off SecureDrop makes too. Browser encryption and `safeshare-cli` avoid it, but they require running trusted code on the sender's device. The page says this to senders.
- **Plaintext that reaches the disk despite the server.** SafeShare never writes the unencrypted upload to disk, but the operating system can. Under memory pressure it may write the process's memory to **swap**, and a crash can leave a **core dump**. Run with swap off or encrypted, and core dumps off. If **malware scanning** is on, the file is streamed to clamd, which can write it to its own temporary directory. Put clamd's temp directory on tmpfs, or leave scanning off for a drop server.
- **Identifying the sender by their connection.** The page itself doesn't hide who connects. Run it in Ghost mode (`ANONYMOUS_MODE=true`) as a Tor onion service, so that no IP address reaches the server and no exact times, IPs or hashes are kept (see [DEPLOYMENT_MODES.md](DEPLOYMENT_MODES.md#ghost-mode)). Without Ghost mode, drops are recorded and logged like any other upload, and SafeShare warns about this at startup.
- **Size and timing.** Padding hides a file's exact size, not its rough size (the bucket is at most about 12% larger than the archive). When a drop arrives is visible to the server and to anyone watching its traffic.
- **What's inside the file.** Cleaning removes hidden metadata, not what the file shows: a name in the text, a face or a landmark in a photo, a printer's tracking dots in a scan.

## What gets cleaned

The server sees the file before encrypting it, so it can clean more types than a browser upload, but its cleaning of Office files is shallower than the browser's.

| Type | Removed |
|------|---------|
| JPEG, PNG | EXIF, GPS, XMP, IPTC and comment data; PNG text and time chunks |
| PDF | the whole document information dictionary (author, title, dates, producer, custom keys), XMP metadata on the document, pages, images and other objects, PieceInfo, the author, dates and ID of each annotation (comments, highlights), and the document ID. **Photos inside a PDF keep their own EXIF data** |
| MP4 family (MP4, MOV, M4V, M4A, 3GP), MP3 | metadata tags (location, dates, device, titles) |
| Word, Excel, PowerPoint (`.docx`, `.xlsx`, `.pptx`) | document properties (`docProps/`, `customXml/`): author, company, dates; the save times of the parts inside the file; and the metadata of JPEG and PNG photos inside it. **Comments and tracked changes keep their authors' names (and the lists of comment authors stay), editing-session IDs stay, an Excel workbook can keep the folder it was last saved in (often including a Windows user name), and a Word file can keep the path of its template.** Senders should remove comments, accept changes and save a copy from a new folder first |

The type is decided from the file's content. A file whose name says it is one of these types but whose content isn't recognised as one (say, `photo.jpg` that is really a text file) is refused, so it can't skip cleaning by being misnamed. Password-protected PDFs can't be cleaned and are refused, and so are PDFs with more than 100,000 objects and Office files with more than 10,000 parts, which would take too much memory to clean (real documents have far fewer). Other types are sent as they are, and the result page says so.

## Setting it up

### 1. Make a key pair, away from the server

On the recipient's own computer, with [age](https://github.com/FiloSottile/age#installation) installed:

```bash
age-keygen -o drop-key.txt
# Public key: age1...
```

`age-keygen -pq` (age 1.3 or later) makes a post-quantum key instead, which also resists future quantum computers. Its public key is about 2,000 characters long.

Keep `drop-key.txt` private and **off the server**: anyone with it can read every drop. Back it up: without it, the drops can't be opened.

### 2. Configure SafeShare

Set the public key (the `age1…` line, or `age-keygen -y drop-key.txt` prints it):

```yaml
services:
  safeshare:
    environment:
      - ANONYMOUS_MODE=true
      - DROP_RECIPIENT=age1yourpublickey...
```

| Variable | Default | Description |
|----------|---------|-------------|
| `DROP_RECIPIENT` | unset (page off) | The one age public key every drop is encrypted to: `age1…`, or post-quantum `age1pq1…`. A private key, several keys, SSH keys and plugin keys are refused, and SafeShare won't start |
| `DROP_MAX_SIZE` | `52428800` (50 MB) | Largest file in bytes. Also capped by `MAX_FILE_SIZE` |
| `DROP_MAX_CONCURRENT` | `2` | How many drops are processed at once (1 to 64). More get a "busy, try again" page (`503`) |
| `DROP_EXPIRATION_HOURS` | `168` (a week) | How long a drop is kept. Also capped by `MAX_EXPIRATION_HOURS` |
| `DROP_ALLOW_WITHOUT_LOGIN` | `false` | Needed when `REQUIRE_AUTH_FOR_UPLOAD=true`: the drop page never asks for a login, so SafeShare refuses to start with both unless you confirm this |

Invalid values stop SafeShare at startup rather than falling back to a default.

**Memory:** drops are held in memory, in two stages. While they arrive, all the drops in progress together may hold at most `DROP_MAX_CONCURRENT` full-size drops' worth of data; a sender only holds memory for what they have actually sent, so slow senders can't lock others out, and new drops are turned away (`503`, try again) when that budget is used up. Once a drop has arrived, cleaning and encrypting it needs one of `DROP_MAX_CONCURRENT` slots and usually up to about three times its size. Allow roughly `DROP_MAX_CONCURRENT × 4 × DROP_MAX_SIZE` (400 MB with the defaults) on top of SafeShare's usual needs. PDFs are the exception: the PDF parser holds every object in memory, so a large PDF made of many small objects can need several hundred MB to clean; ones with more than 100,000 objects are refused. Office files aren't inflated to be cleaned, apart from their two small structural XML files and the photos in them.

Drops share the upload rate limit (`RATE_LIMIT_UPLOAD`, per IP address; over Tor, all visitors share one).

### 3. Publish the public key somewhere else

The result page shows the key the drop was encrypted to ("Locked with"). Publish your public key somewhere the server doesn't control, such as your website or your social media profile, so that senders can check that the two match. A compromised server could swap in its own key; a sender who compares would notice.

## Sending

Tell senders:

1. Open the server's `/drop` page, ideally in Tor Browser. It works on the Safest setting.
2. Choose the file, write a message if you like, and press **Encrypt and send**.
3. Write down the code on the next page. It isn't shown again. Check that "Locked with" matches the recipient's published key.
4. Give the code to the recipient the way you agreed.

The main SafeShare page shows a pointer to `/drop` to visitors who have JavaScript turned off.

## Receiving

With the code from the sender, download the file. Over Tor if the server is an onion service:

```bash
curl -o drop.tar.age https://share.example.com/api/claim/CODE
# or: torsocks curl -o drop.tar.age http://youronionaddress.onion/api/claim/CODE
```

Opening the link in a browser downloads the same file. Then decrypt and unpack it into an empty folder:

```bash
mkdir drop && cd drop
age -d -i ../drop-key.txt ../drop.tar.age | tar -xvf -
```

On Windows, `tar` is built in:

```powershell
age -d -i drop-key.txt -o drop.tar drop.tar.age
tar -xvf drop.tar
```

You get the file under the name the sender gave it, and `message.txt` if they wrote one. Archive entries have no owner and a 1970 date, so they don't reveal the sender's account or when they made the file. The zero-byte padding after the archive is ignored by tar.

**Treat what you receive as untrusted.** Open documents in a disposable environment or offline (SecureDrop's guidance on [handling submissions](https://docs.securedrop.org/en/stable/journalist/journalist.html) applies). SafeShare's archive only contains plain files, but if the server was compromised it could have built a harmful one: unpack into an empty folder, and list it first with `tar -tvf` if in doubt.

## Checking the page

`safeshare-cli verify` (see [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md)) checks that `/drop` is the page published with the release. The page has no script at all, so there is nothing that could run in the sender's browser, but a changed page could still say something different or post somewhere else. The result page differs on every drop and isn't checked.
