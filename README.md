# SafeBro

Audited, guarded Rails console access, with a built-in review UI. One gem.

- **Records** every console session: who, why, and every command (encrypted at rest).
- **Locks** sensitive data until the person runs `unlock!` and explains why: encrypted attributes, credentials, secret `ENV` values, key files, protected systems like Redis or Elasticsearch.
- **Checks** each command before it runs: forbidden ones are blocked, suspicious ones are flagged.
- **Protects its own audit trail** from the console.
- **Lets auditors review** sessions in a built-in UI: approve, or flag with notes. It's a section of the [BroHub](https://github.com/rubydevro/bro_hub) dashboard, the same shell [EnvBro](https://github.com/rubydevro/env_bro) uses.

It covers what [console1984](https://github.com/basecamp/console1984) and [audits1984](https://github.com/basecamp/audits1984) do together, rebuilt from scratch as a single gem. Rails 7.1+, Ruby 3.2+, IRB 1.13+.

> **Read [What this is not](#what-this-is-not).** SafeBro is a deterrent and an audit trail. It is not a sandbox.

## Install

```ruby
gem "safe_bro"
```

```sh
bin/rails generate safe_bro:install   # BroHub (mount + initializer), then SafeBro's initializer and migrations. --mount-path=/bro_hub skips the question
bin/rails db:migrate
```

The generator pulls in [BroHub](https://github.com/rubydevro/bro_hub) (a dependency) and mounts it once:

```ruby
mount BroHub::Engine => "/bro_hub"   # the review UI is at /bro_hub/safe_bro
```

Then in `config/initializers/safe_bro.rb` say who may review sessions:

```ruby
SafeBro.configure do |config|
  config.can_audit = ->(user) { user.admin? }
end
```

### One dashboard for all the Bro gems

SafeBro shows up as a **SafeBro · audit** section in BroHub's sidebar (Sessions, Flagged commands, Unlocks, Rules), only for people who pass `can_audit`. Who is signed in is configured **once**, in BroHub (`BroHub.configure { |c| c.current_user = ... }`, which by default calls `current_user` on your `ApplicationController`). SafeBro uses that unless you set `config.current_user` / `config.user_label` yourself.

- SafeBro works with just BroHub installed. Add [EnvBro](https://github.com/rubydevro/env_bro) and it appears as a second section, with no extra mount or setup.
- Already mounting `SafeBro::Engine` yourself? That keeps working: you get the same look with only the SafeBro section. Remove your mount to join the dashboard.

By default SafeBro acts only in `production`. Nothing is installed by loading the gem; protection starts when a console starts (`config.protected_environments` to change it).

### Telling SafeBro who is at the console

SafeBro reads the user from `CONSOLE_USER`. **A name is only as trustworthy as whatever sets it.** Prefer the server setting it, not the client:

```
# ~/.ssh/authorized_keys on the server, one line per person
environment="CONSOLE_USER=jane" ssh-ed25519 AAAA... jane@laptop
```

(needs `PermitUserEnvironment yes` in `sshd_config`). A client-side `SetEnv CONSOLE_USER=...` works too, but then anyone can claim to be anyone.

With no `CONSOLE_USER` the console refuses to start. Use `config.username_resolver = -> { ... }` to resolve it another way, or `config.ask_for_username_if_empty = true` to ask on the terminal.

## What it looks like

```
$ rails console

You have access to production data here. That's a big deal. ...

jane, why are you using this console today?
> Fixing invoice 12, ticket #4521

myapp(prod):001> Invoice.find(12).customer.email
=> "{\"p\":\"iu6+LfnNlurC6sL++J...\"}"   # an encrypted attribute, shown as ciphertext while locked

myapp(prod):002> ENV["STRIPE_SECRET_KEY"]
SafeBro: flagged for review - Access to env is protected. (STRIPE_SECRET_KEY) Run unlock! ...

myapp(prod):003> unlock! :env
Before you access sensitive data ... say why and where we can find the consent or ticket.
> Ticket #4521: customer asked us to rotate their key

Unlocked. We pay extra close attention to everything you do now. Type lock! to protect it again.
```

Commands:

| Command | What it does |
| --- | --- |
| `unlock!` | Unlock everything. Asks for a justification and records it. |
| `unlock! :credentials` | Unlock only some resources (`encrypted_data`, `credentials`, `env`, `files`, `network`). |
| `lock!` | Lock again. |

Everything typed while unlocked is linked to that justification in the review UI.

## What is protected

| Resource | While locked |
| --- | --- |
| `encrypted_data` | Active Record encrypted attributes read as ciphertext, and can't be written. (Needs Active Record Encryption in your app.) |
| `credentials` | `Rails.application.credentials`, `secret_key_base`, `key_generator`, `message_verifier`, and the encrypted file/key classes raise when called from the console. |
| `env` | `ENV["SOME_SECRET"]` raises for names matching `config.protected_env_patterns`. Dumping `ENV` (`to_h`, `each`, `inspect`, ...) filters those values. |
| `files` | `master.key`, `credentials/*.key` and `.env*` files can't be read or copied (`File`, `IO`, `Pathname`, `open`, `FileUtils`). |
| `network` | Connections to `config.protected_urls` fail, including writes on connections opened earlier (a pool). |

Library code is not affected: Rails reading its credentials while it runs your command works. Only calls made **directly from what the person typed** are blocked (SafeBro tells them apart by the file name IRB evaluates code under), except `network` and `inspect`, which apply to anything running during a command.

## Guardrails

Each command is checked before it runs:

- **Blocked**: reopening protected classes (`class ActiveRecord::Base`, ...), referencing `SafeBro`/`IRB`/`ObjectSpace`, and calling `eval`, `instance_eval`, `class_eval`, `system`, `exec`, `spawn`, backticks, `IO.popen`, ...
- **Flagged**: commands that mention `secret`, `credentials`, `ENV`, `master.key`, ... run, but are marked suspicious.
- **Runtime backstops** for the obvious ways around static checks: `send(:eval, ...)`, `Object.const_get("Safe" + "Bro")`, `"SafeBro".constantize`, and so on.
- **The audit trail can't be touched**: any SQL mentioning SafeBro's tables from the console raises.
- **Frozen internals**: SafeBro's classes and config are frozen once installed, so they can't be monkey patched.

All of it is configurable:

```ruby
config.forbidden_methods += [ "Kernel#open" ]          # "Owner#method" or "Owner.method"
config.forbidden_constants[:locked] += [ "Net::HTTP" ] # only while locked (or :always)
config.suspicious_terms += [ "DROP TABLE" ]
config.protected_resources = %i[ encrypted_data credentials env ]
config.protected_urls = [ "redis://cache.internal:6379" ]
config.protected_env_patterns += [ /STRIPE/ ]
config.protected_file_patterns += [ %r{config/.*\.pem\z} ]
```

## Reviewing sessions

Mount point is chosen by the generator (default `/bro_hub`, SafeBro at `/bro_hub/safe_bro`). The sidebar has four pages:

- **Sessions**: a filterable list (review tab, user, dates, "needs attention" = unlocked or flagged commands). Open one to read what happened, and approve it or flag it with notes. After deciding you land on the next pending session within the same filter.
- **Flagged commands**: every command that was blocked or ran and looked suspicious, newest first, each linking to its session.
- **Unlocks**: who unlocked sensitive data, which resources, and the reason they gave.
- **Rules**: a read-only view of what's locked, blocked and flagged right now (never keys or URL passwords). Change it in the initializer.

- Audits are append-only; the latest one decides the status and the history is kept.
- An auditor can't review their own session (`config.allow_self_audit = true` to allow).
- Command text and audit notes are encrypted at rest with a key derived from `secret_key_base` (or `config.encryption_key`, 32 bytes).
- The UI sends `Cache-Control: no-store` and requires SSL in production.
- Hiding the section from someone is navigation only: every SafeBro page checks `can_audit` itself.

### Notifications

SafeBro instruments `ActiveSupport::Notifications`, so alerting is yours to wire up:

```ruby
ActiveSupport::Notifications.subscribe(/\.safe_bro\z/) do |name, _start, _finish, _id, payload|
  # session_started, unlocked, command_flagged, session_flagged
  SecurityMailer.console_event(name, payload).deliver_later
end
```

### Retention

Sessions older than `config.retention` (90 days) are removed, flagged ones are kept (`config.keep_flagged`). Schedule `SafeBro::PurgeJob` (daily) or run `bin/rails safe_bro:purge`. `config.retention = nil` keeps everything.

### `rails runner`

`config.audit_runner = true` also records `rails runner` invocations as sessions (`CONSOLE_USER` and `CONSOLE_REASON` are used if set). Runners aren't shielded; they run scripts, not a person exploring.

### Non-interactive consoles

With no terminal there is nobody to ask, so set `CONSOLE_REASON` (e.g. `CONSOLE_REASON="deploy check" rails console`). `unlock!` always needs a terminal.

## For gem authors

Anything sensitive your gem exposes can use the same lock:

```ruby
config.protected_resources += [ :billing ]   # host app config

SafeBro.guard!(:billing)                     # in your code, before revealing something
```

`SafeBro.guard!` does nothing outside a console command, and raises `SafeBro::ProtectedResource` inside one until the person runs `unlock! :billing`.

## What this is not

Ruby is too dynamic to sandbox. Someone determined who has a console on your production box can get around the static checks and the runtime guards, for example by reading process memory, speaking to the database driver directly, using `dbconsole`, or loading code from disk. SafeBro raises the cost, catches mistakes, makes honest people stop and explain, and leaves a record that dishonest attempts show up in. That's valuable, but it's not a boundary.

If you need a boundary, build it outside Ruby:

- Don't leave the credentials key on machines people shell into. Deliver it to the app process only.
- Give console users a database role that can't read what they shouldn't.
- Control who can SSH in, and set `CONSOLE_USER` from the server side.
- Have an auditor actually review sessions. An unreviewed audit trail deters nothing.

Not covered: `rails dbconsole`, a raw `psql`/`mysql` session, other process managers or shells, and Pry (SafeBro hooks IRB).

### Where they connected from

SafeBro stores the client IP with each session and shows it on the session page, with a note when the same user has also come from other addresses. It reads `CONSOLE_CLIENT_IP`, then `SSH_CLIENT` / `SSH_CONNECTION` (set by sshd, so a user can't change them), and ignores anything that isn't an IP address. Behind a wrapper that starts a container, pass it in: `docker run -e CONSOLE_USER -e CONSOLE_CLIENT_IP="${SSH_CLIENT%% *}" ...`. Or set `config.client_ip_resolver`. It is the NAT or VPN address, not necessarily the person's machine.

### Shared audit log

Sessions, commands and unlocks stay in SafeBro's own tables. The key moments (a session starting, an unlock with its justification, a flagged command, an auditor's verdict) are also written to BroHub's shared audit table, so they show up in BroHub's combined audit log next to EnvBro and CacheBro. Commands, their output and auditors' notes are never copied there. Writing it is best effort: if BroHub's migration hasn't run, consoles still open and SafeBro's own tables are still written. The console can't read or change the shared table either (it is covered by the same guard as SafeBro's tables).

Upgrading from 0.2.x or earlier: `bundle update safe_bro`, then `bin/rails g bro_hub:install` (copies BroHub's audit table migration; SafeBro's own tables are unchanged) and `bin/rails db:migrate`. From 0.1.x also run `bin/rails safe_bro:install:migrations` first.

## Differences from console1984 + audits1984

- One gem, one engine, one migration set (no shared base-model coupling between two gems), and a UI that plugs into the same dashboard as the other Bro gems.
- Rails credentials, `ENV` and key files are first-class protected resources, not just encrypted attributes.
- `unlock!` can be scoped to a resource, and gem authors can add their own with `SafeBro.guard!`.
- Commands are encrypted with SafeBro's own key, so Active Record Encryption needn't be configured to use it (it's only needed for the `encrypted_data` protection).
- Static checks use Ruby's tokenizer rather than a parser, so code that doesn't parse can't hide a name from them.
- Audits are append-only with history, auditors can't approve themselves, and flagged sessions survive retention.
- `rails runner` sessions can be recorded; notifications are `ActiveSupport::Notifications`.
- Not carried over: Pry and other console support (SafeBro hooks IRB only).

## Switching from console1984 + audits1984

1. **Don't run both.** Both hook IRB at startup and would record every command twice, so remove `console1984` and
   `audits1984` from the Gemfile when you add `safe_bro`, and remove their mount (`mount Audits1984::Engine`) and
   initializer settings. `bin/rails g bro_hub:install --remove-direct-mounts` only retires SafeBro/EnvBro mounts, so do this by hand.
2. **Existing audit data stays where it is.** SafeBro uses its own `safe_bro_*` tables and doesn't read console1984's
   (`console1984_*`, `audits1984_*`). Nothing is migrated: the old sessions can't be reviewed in SafeBro's UI.
   Keep the old tables (read them from a console or SQL) for as long as you need the history, then drop them in a migration.
   Sessions already encrypted with Active Record Encryption need those keys for as long as you keep them.
3. Map the settings: console1984's `protected_environments` → the same option in SafeBro
   in `config/initializers/safe_bro.rb`; audits1984's auditor check → `config.can_audit`.
4. Set `CONSOLE_USER` for everyone (see above), then run `bin/rails g safe_bro:install` and `bin/rails db:migrate`.

## Development

```sh
bin/rails test                                                    # Rails 8.x
BUNDLE_GEMFILE=gemfiles/rails_7_1.gemfile bundle exec rails test  # Rails 7.1
bin/rubocop
```

The suite includes tests that boot a real `rails console` in `test/dummy`, one with piped input and one driven through a pseudo-terminal, to prove the IRB hook works on the IRB you have.

## License

MIT.
