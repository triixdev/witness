# Privacy

Last updated: 6 November 2026

Witness is a small command line tool, a Switch room template and a static website.

**What the tool does with your data.** It runs on your machine, makes no network calls and has no
telemetry. Receipts are written to a `.witness/` folder in your project. Nothing is uploaded by Witness.

**What reaches the chat.** The receipt block you or your agent pastes goes to your chat app (Slack, Teams,
Discord, Telegram or Mattermost) and to the AI agent provider you chose. Witness redacts known secret formats,
email addresses, Indian PAN and Aadhaar numbers, phone numbers and home folder names from command output
before the block is created. Redaction is pattern based and best effort. It can miss things. Read a receipt
before you post it if the project is sensitive.

**Switch.** Switch Console and Switch Core have their own telemetry settings, described in the Switch
repository. Witness does not change them.

**This website.** No cookies, no analytics, no third party scripts, no fonts loaded from other sites, no forms.
The host serving the files (for example GitHub Pages) may keep ordinary access logs under its own policy.

**Contact and deletion.** Witness holds no accounts or personal data, so there is nothing to delete on our side.
For questions, open an issue at https://github.com/triixdev/witness/issues. Maintainer address for records: 299201596+triixdev@users.noreply.github.com.
