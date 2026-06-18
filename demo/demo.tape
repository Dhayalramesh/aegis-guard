# Aegis Guard — terminal demo
#
# Renders to demo/demo.gif with VHS (https://github.com/charmbracelet/vhs):
#   npm install -g aegis-agent-guard      # provides the `aegis` command
#   vhs demo/demo.tape
#
# Every command below is real; nothing is faked.

Output demo/demo.gif

Set Shell "bash"
Set FontSize 19
Set Width 1180
Set Height 760
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 50ms

# --- setup (hidden): isolated scratch dir + its own audit log ---
Hidden
Type "cd $(mktemp -d) && export AEGIS_LOG=$PWD/audit.log && clear"
Enter
Show

Type "# Aegis screens what an AI agent does — BEFORE it happens."
Sleep 1s
Enter
Sleep 800ms

Type "aegis check 'rm -rf /'"
Sleep 500ms
Enter
Sleep 2s

Type "# Obfuscation doesn't get past it — quotes are normalized away."
Sleep 800ms
Enter
Type "aegis check \"r''m -rf /\""
Sleep 500ms
Enter
Sleep 2s

Type "# The database wipe that kicked all this off:"
Sleep 800ms
Enter
Type "aegis check 'psql -c \"DROP TABLE users\"'"
Sleep 500ms
Enter
Sleep 2s

Type "# It guards file writes too — not just shell commands."
Sleep 800ms
Enter
Type "aegis check --path ~/.ssh/id_rsa"
Sleep 500ms
Enter
Sleep 2s

Type "# Every decision lands in a tamper-evident log."
Sleep 800ms
Enter
Type "aegis log --verify"
Sleep 500ms
Enter
Sleep 2s

Type "# What if the agent edits the log to cover its tracks?"
Sleep 800ms
Enter
Type "sed -i 's/\"block\"/\"allow\"/' $AEGIS_LOG   # tamper"
Sleep 500ms
Enter
Sleep 1s
Type "aegis log --verify"
Sleep 500ms
Enter
Sleep 2.5s

Type "# Caught. The agent can't quietly rewrite history."
Sleep 800ms
Enter
Sleep 3s
