<?php
// Auto-generated copy of data/detection-knowledge.json so the scan works even if the data/ folder is not uploaded.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) { http_response_code(404); exit; }
return <<<'CG_JSON_END'
{
  "version": "2026.10.07-v3",
  "language": "en",
  "reviewed_on": "2026-10-07",
  "thresholds": {
    "high": 60,
    "suspicious": 30
  },
  "sources": [
    {
      "id": "ftc_phishing",
      "publisher": "FTC",
      "title": "Recognize and avoid phishing",
      "url": "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_scams",
      "publisher": "FTC",
      "title": "Avoid a scam",
      "url": "https://consumer.ftc.gov/articles/how-avoid-scam",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "fbi_bec",
      "publisher": "FBI",
      "title": "Business email compromise",
      "url": "https://www.fbi.gov/how-we-can-help-you/common-frauds-and-scams/business-email-compromise",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_task",
      "publisher": "FTC",
      "title": "Task scams",
      "url": "https://consumer.ftc.gov/consumer-alerts/2025/08/how-spot-avoid-task-scams",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_jobs",
      "publisher": "FTC",
      "title": "Job scams",
      "url": "https://consumer.ftc.gov/articles/job-scams",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_tech",
      "publisher": "FTC",
      "title": "Tech support scams",
      "url": "https://consumer.ftc.gov/articles/how-spot-avoid-and-report-tech-support-scams",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ic3_investment",
      "publisher": "FBI IC3",
      "title": "Cryptocurrency investment schemes",
      "url": "https://www.ic3.gov/PSA/2023/PSA230314",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ic3_recovery",
      "publisher": "FBI IC3",
      "title": "Cryptocurrency recovery schemes",
      "url": "https://www.ic3.gov/PSA/2023/psa230811",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_tolls",
      "publisher": "FTC",
      "title": "Unpaid toll text scams",
      "url": "https://consumer.ftc.gov/consumer-alerts/2025/01/got-text-about-unpaid-tolls-its-probably-scam",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_qr",
      "publisher": "FTC",
      "title": "Harmful links in QR codes",
      "url": "https://consumer.ftc.gov/consumer-alerts/2023/12/scammers-hide-harmful-links-qr-codes-steal-your-information",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_captcha",
      "publisher": "FTC",
      "title": "CAPTCHA command scams",
      "url": "https://consumer.ftc.gov/consumer-alerts/2026/06/how-spot-captcha-scam",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ms_phishing",
      "publisher": "Microsoft",
      "title": "Protect yourself from phishing",
      "url": "https://support.microsoft.com/en-us/security/protect-yourself-from-phishing",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "fbi_extortion",
      "publisher": "FBI",
      "title": "Financial sextortion threats",
      "url": "https://www.fbi.gov/contact-us/field-offices/baltimore/news/sextortion-a-growing-threat-targeting-minors",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "ftc_sms",
      "publisher": "FTC",
      "title": "Spam text messages",
      "url": "https://consumer.ftc.gov/articles/how-recognize-and-report-spam-text-messages",
      "reviewed_on": "2026-10-07"
    },
    {
      "id": "openphish",
      "publisher": "OpenPhish",
      "title": "Phishing feed documentation",
      "url": "https://www.openphish.com/phishing_feeds.html",
      "reviewed_on": "2026-10-07"
    }
  ],
  "rules": [
    {
      "id": "urgency",
      "label": "Time pressure or immediate action",
      "group": "pressure",
      "weight": 8,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:urgent|immediately|act now|right now|final notice|last warning|within (?:24|48|12|2) hours?)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "account_warning",
      "label": "Account access threatened",
      "group": "account",
      "weight": 22,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:account|card|mailbox|subscription|access)\\b.{0,50}\\b(?:suspend(?:ed|sion)?|locked|restricted|disabled|terminat(?:ed|ion)|deactivat(?:ed|ion)|blocked|expir(?:ed|es))\\b",
        "\\b(?:suspended|locked|restricted) (?:account|card|mailbox)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "verify_action",
      "label": "Request to verify account or identity",
      "group": "verification",
      "weight": 22,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:verify|confirm|update|reactivate|restore)\\b.{0,25}\\b(?:account|identity|billing|payment|details|information|access)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "credential_request",
      "label": "Request to disclose a password or financial identifier",
      "group": "credentials",
      "weight": 42,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:send|reply|provide|enter|submit|share|re-enter|confirm)\\b.{0,45}\\b(?:password|pin|ssn|social security|cvv|card number|bank details|bank info|account number|routing number)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "otp_request",
      "label": "Request to share a one-time sign-in code",
      "group": "credentials",
      "weight": 70,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:send|tell|share|reply|forward|give|read)\\b.{0,40}\\b(?:otp|one.time (?:code|password|passcode)|verification code|authentication code|security code|six.digit code|6.digit code)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "seed_request",
      "label": "Request to disclose a wallet recovery secret",
      "group": "credentials",
      "weight": 80,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:enter|send|share|provide|submit|verify)\\b.{0,45}\\b(?:seed phrase|recovery phrase|private key|12.word phrase|24.word phrase)\\b"
      ],
      "sources": [
        "ic3_investment"
      ]
    },
    {
      "id": "payment_update",
      "label": "Payment failure plus requested billing change",
      "group": "account",
      "weight": 22,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:payment fail(?:ed|ure)|billing problem|payment declined|update your payment)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "gift_payment",
      "label": "Payment demanded using gift cards",
      "group": "payment",
      "weight": 42,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:pay|buy|purchase|send|get)\\b[^,.;!?]{0,45}\\b(?:gift cards?|itunes cards?|steam cards?|apple cards?)\\b"
      ],
      "sources": [
        "ftc_scams",
        "fbi_bec"
      ]
    },
    {
      "id": "gift_codes",
      "label": "Request for gift-card numbers or photographs",
      "group": "payment",
      "weight": 70,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:send|share|email|text|give)\\b.{0,50}\\b(?:codes? on the back|numbers? on the back|gift card codes?|gift card numbers?|serial numbers?|photos? of (?:the )?cards?)\\b"
      ],
      "sources": [
        "ftc_scams",
        "fbi_bec"
      ]
    },
    {
      "id": "crypto_payment",
      "label": "Request to send cryptocurrency",
      "group": "payment",
      "weight": 28,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:pay|send|transfer|deposit)\\b.{0,40}\\b(?:bitcoin|btc|usdt|crypto(?:currency)?|ethereum|ether|wallet)\\b"
      ],
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "advance_fee",
      "label": "Upfront fee requested",
      "group": "payment",
      "weight": 28,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:pay|send|deposit|transfer)\\b.{0,40}\\b(?:fee|tax|charges?|deposit)\\b",
        "\\b(?:processing fee|clearance fee|activation fee|release fee)\\b"
      ],
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "prize",
      "label": "Unexpected winnings or prize claim",
      "group": "prize",
      "weight": 32,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:you (?:have )?won|lottery winner|claim your prize|inheritance funds|unclaimed inheritance|cash prize|international.{0,15}lottery)\\b"
      ],
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "payment_change",
      "label": "Changed bank or payment instructions",
      "group": "payment_change",
      "weight": 38,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:new|updated|changed|different)\\b.{0,25}\\b(?:bank account|bank details|payment instructions|routing number|wire instructions)\\b",
        "\\b(?:bank account|bank details|payment instructions)\\b.{0,25}\\b(?:changed|updated)\\b"
      ],
      "sources": [
        "fbi_bec"
      ]
    },
    {
      "id": "secrecy",
      "label": "Request to bypass independent verification",
      "group": "secrecy",
      "weight": 25,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:keep (?:this|it) (?:confidential|secret)|do not (?:call|tell anyone|contact)|don.t (?:call|tell anyone)|without (?:calling|approval)|bypass.{0,12}approval)\\b"
      ],
      "sources": [
        "fbi_bec",
        "ftc_scams"
      ]
    },
    {
      "id": "wire_action",
      "label": "Request to wire or redirect a payment",
      "group": "transfer",
      "weight": 20,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:wire|transfer|remit|send)\\b.{0,35}\\b(?:payment|money|funds|balance|deposit|bank account)\\b"
      ],
      "sources": [
        "fbi_bec"
      ]
    },
    {
      "id": "fake_check",
      "label": "Deposit a check and send money onward",
      "group": "fake_check",
      "weight": 65,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\bdeposit\\b.{0,40}\\b(?:check|cheque)\\b"
      ],
      "sources": [
        "ftc_jobs"
      ],
      "all_regex": [
        "\\b(?:send|return|forward|wire|buy)\\b.{0,50}\\b(?:difference|rest|remainder|vendor|equipment|money|gift cards?)\\b"
      ]
    },
    {
      "id": "job_fee",
      "label": "Payment required to obtain employment",
      "group": "employment",
      "weight": 48,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:pay|deposit|send)\\b.{0,40}\\b(?:training fee|registration fee|equipment fee|application fee)\\b",
        "\\bpay\\b.{0,25}\\b(?:get (?:the |a )?job|start (?:the )?job)\\b"
      ],
      "sources": [
        "ftc_jobs"
      ]
    },
    {
      "id": "task_work",
      "label": "Task-platform or product-boosting offer",
      "group": "employment",
      "weight": 28,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:product boosting|optimization tasks?|rating products?|complete.{0,15}tasks.{0,25}commission|task platform)\\b"
      ],
      "sources": [
        "ftc_task"
      ]
    },
    {
      "id": "unlock_earnings",
      "label": "Payment required to release purported earnings",
      "group": "withdrawal",
      "weight": 50,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:deposit|pay|recharge|top up)\\b.{0,65}\\b(?:unlock|withdraw|release|earnings|tasks)\\b",
        "\\b(?:unlock|withdraw|release)\\b.{0,45}\\b(?:earnings|profits|funds)\\b.{0,45}\\b(?:deposit|fee|tax)\\b"
      ],
      "sources": [
        "ftc_task",
        "ic3_investment"
      ]
    },
    {
      "id": "guaranteed_profit",
      "label": "Guaranteed or risk-free investment profit",
      "group": "investment",
      "weight": 48,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:guaranteed (?:returns?|profits?)|risk.free (?:investment|profit|returns?)|double your (?:money|investment)|(?:10|20|30|50)% (?:daily|weekly) (?:return|profit))\\b"
      ],
      "sources": [
        "ic3_investment"
      ]
    },
    {
      "id": "recovery_fee",
      "label": "Fee demanded for recovery of lost cryptocurrency",
      "group": "recovery",
      "weight": 48,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:recover|recovery|retrieve)\\b.{0,40}\\b(?:crypto|bitcoin|stolen funds|lost funds|your funds)\\b"
      ],
      "sources": [
        "ic3_recovery"
      ],
      "all_regex": [
        "\\b(?:fee|pay|deposit|upfront|retainer)\\b"
      ]
    },
    {
      "id": "arrest_threat",
      "label": "Threat of arrest or legal punishment",
      "group": "coercion",
      "weight": 38,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:arrest warrant|you will be arrested|avoid arrest|face arrest|deported|license (?:will be )?suspended|legal action)\\b"
      ],
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "safe_account",
      "label": "Request to transfer savings for supposed protection",
      "group": "coercion",
      "weight": 70,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:transfer|move|send)\\b.{0,45}\\b(?:money|funds|savings)\\b.{0,55}\\b(?:safe account|secure account|protect|safeguard)\\b"
      ],
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "extortion",
      "label": "Threat to release private images or recordings",
      "group": "coercion",
      "weight": 65,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:release|publish|share|send|leak)\\b.{0,45}\\b(?:intimate|explicit|private|nude|webcam|video|photos)\\b"
      ],
      "sources": [
        "fbi_extortion"
      ],
      "all_regex": [
        "\\b(?:pay|bitcoin|money|unless|contacts)\\b"
      ]
    },
    {
      "id": "remote_access",
      "label": "Request to install remote-access software",
      "group": "remote_access",
      "weight": 40,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:install|download|open|enable|grant)\\b.{0,45}\\b(?:anydesk|teamviewer|remote access|remote desktop|screen sharing)\\b"
      ],
      "sources": [
        "ftc_tech"
      ]
    },
    {
      "id": "virus_claim",
      "label": "Computer infection or blocking claim",
      "group": "tech_support",
      "weight": 28,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:computer|device|windows|pc)\\b.{0,35}\\b(?:infected|blocked|virus|compromised)\\b"
      ],
      "sources": [
        "ftc_tech"
      ]
    },
    {
      "id": "support_call",
      "label": "Urgent technical-support call request",
      "group": "tech_support",
      "weight": 25,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:call|contact)\\b.{0,30}\\b(?:support|technician|helpdesk)\\b.{0,25}\\b(?:now|immediately|urgent)\\b"
      ],
      "sources": [
        "ftc_tech"
      ]
    },
    {
      "id": "macro_action",
      "label": "Instruction to enable macros or bypass protection",
      "group": "execution",
      "weight": 65,
      "family": "malware",
      "type": "text",
      "any_regex": [
        "\\b(?:enable (?:macros|content)|disable (?:antivirus|security|protected view)|turn off.{0,15}antivirus)\\b"
      ],
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "captcha",
      "label": "Human-verification pretext",
      "group": "captcha",
      "weight": 5,
      "family": "malware",
      "type": "text",
      "any_regex": [
        "\\b(?:captcha|verify you(?:.re| are) human|prove you are human|human verification)\\b"
      ],
      "sources": [
        "ftc_captcha"
      ]
    },
    {
      "id": "run_command",
      "label": "Instruction to paste or run a system command",
      "group": "execution",
      "weight": 20,
      "family": "malware",
      "type": "text",
      "any_regex": [
        "\\b(?:windows\\s*\\+\\s*r|win\\s*\\+\\s*r|ctrl\\s*\\+\\s*v|paste.{0,20}(?:command|powershell|terminal)|run.{0,15}powershell)\\b"
      ],
      "sources": [
        "ftc_captcha"
      ]
    },
    {
      "id": "delivery_problem",
      "label": "Delivery or shipping problem with requested action",
      "group": "delivery",
      "weight": 25,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:package|parcel|delivery|shipment)\\b.{0,40}\\b(?:held|failed|on hold|incomplete|reschedule|undeliverable)\\b",
        "\\b(?:incomplete|incorrect) address\\b"
      ],
      "sources": [
        "ftc_sms"
      ]
    },
    {
      "id": "delivery_fee",
      "label": "Redelivery or customs fee request",
      "group": "delivery_fee",
      "weight": 35,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:redelivery fee|delivery fee|customs fee|rescheduling fee)\\b"
      ],
      "sources": [
        "ftc_sms"
      ]
    },
    {
      "id": "unpaid_toll",
      "label": "Claim of overdue toll charges",
      "group": "toll",
      "weight": 35,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:unpaid|overdue|outstanding)\\b.{0,15}\\btolls?\\b",
        "\\btoll\\b.{0,20}\\b(?:balance|payment due)\\b"
      ],
      "sources": [
        "ftc_tolls"
      ]
    },
    {
      "id": "qr_action",
      "label": "Request to scan a QR code",
      "group": "qr",
      "weight": 8,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\bscan\\b.{0,20}\\bqr code\\b"
      ],
      "sources": [
        "ftc_qr"
      ]
    },
    {
      "id": "refund_lure",
      "label": "Refund request for financial details",
      "group": "refund",
      "weight": 38,
      "family": "phishing",
      "type": "text",
      "any_regex": [
        "\\b(?:refund|reimbursement)\\b"
      ],
      "sources": [
        "ftc_phishing"
      ],
      "all_regex": [
        "\\b(?:enter|provide|confirm|send)\\b.{0,30}\\b(?:bank|card|account|details|information)\\b"
      ]
    },
    {
      "id": "romance_money",
      "label": "Relationship pretext combined with a money request",
      "group": "romance",
      "weight": 40,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:love you|our future together|my love|my darling)\\b"
      ],
      "sources": [
        "ic3_investment"
      ],
      "all_regex": [
        "\\b(?:send|wire|transfer)\\b.{0,40}\\b(?:money|funds|bitcoin|crypto)\\b"
      ]
    },
    {
      "id": "money_mule",
      "label": "Commission offered for forwarding funds",
      "group": "money_mule",
      "weight": 65,
      "family": "scam",
      "type": "text",
      "any_regex": [
        "\\b(?:receive|accept)\\b.{0,30}\\b(?:money|funds|payments)\\b"
      ],
      "sources": [
        "fbi_bec"
      ],
      "all_regex": [
        "\\b(?:forward|transfer|send)\\b.{0,40}\\b(?:rest|remainder|funds|money)\\b",
        "\\b(?:commission|percentage|keep \\d+)\\b"
      ]
    },
    {
      "id": "url_shortener",
      "label": "Shortened URL hides its destination",
      "group": "url_context",
      "weight": 10,
      "family": "phishing",
      "type": "feature",
      "feature": "shortener",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_ip",
      "label": "URL uses an IP address instead of a domain",
      "group": "url_context",
      "weight": 15,
      "family": "phishing",
      "type": "feature",
      "feature": "ip_host",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_userinfo",
      "label": "URL contains misleading user information before @",
      "group": "url_identity",
      "weight": 35,
      "family": "phishing",
      "type": "feature",
      "feature": "userinfo",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_brand",
      "label": "Brand-like hostname is outside listed brand domains",
      "group": "url_identity",
      "weight": 45,
      "family": "phishing",
      "type": "feature",
      "feature": "brand_mismatch",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_punycode",
      "label": "Internationalized hostname needs manual inspection",
      "group": "url_context",
      "weight": 8,
      "family": "phishing",
      "type": "feature",
      "feature": "punycode",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_insecure",
      "label": "Unencrypted HTTP link",
      "group": "url_context",
      "weight": 5,
      "family": "phishing",
      "type": "feature",
      "feature": "http",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_encoded",
      "label": "Encoded hostname or concealed URL characters",
      "group": "url_context",
      "weight": 12,
      "family": "phishing",
      "type": "feature",
      "feature": "encoded_host",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "text_obfuscated",
      "label": "Hidden characters or defanged link notation",
      "group": "url_context",
      "weight": 8,
      "family": "phishing",
      "type": "feature",
      "feature": "obfuscated",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "url_download",
      "label": "Link points to an executable or script file",
      "group": "download",
      "weight": 40,
      "family": "malware",
      "type": "feature",
      "feature": "executable",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "account_capture",
      "label": "Account threat combined with verification and a link",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "account_warning",
          "payment_update"
        ],
        [
          "verify_action",
          "credential_request"
        ],
        [
          "url_present",
          "qr_action"
        ]
      ],
      "min_score": 80,
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "credentials_link",
      "label": "Sensitive information requested through a link",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "credential_request"
        ],
        [
          "url_present",
          "qr_action"
        ]
      ],
      "min_score": 75,
      "sources": [
        "ftc_phishing"
      ]
    },
    {
      "id": "brand_login",
      "label": "Brand-like external hostname with sign-in or verification request",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "url_brand",
          "url_userinfo"
        ],
        [
          "verify_action",
          "credential_request",
          "account_warning"
        ]
      ],
      "min_score": 85,
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "lottery_fee",
      "label": "Prize or inheritance claim requires money or private details",
      "group": "combinations",
      "weight": 0,
      "family": "scam",
      "type": "combination",
      "all_signals": [
        [
          "prize"
        ],
        [
          "advance_fee",
          "crypto_payment",
          "gift_payment",
          "credential_request"
        ]
      ],
      "min_score": 90,
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "bec_redirect",
      "label": "Changed payment instructions combined with transfer or secrecy",
      "group": "combinations",
      "weight": 0,
      "family": "scam",
      "type": "combination",
      "all_signals": [
        [
          "payment_change"
        ],
        [
          "wire_action",
          "secrecy",
          "urgency"
        ]
      ],
      "min_score": 80,
      "sources": [
        "fbi_bec"
      ]
    },
    {
      "id": "task_deposit",
      "label": "Task work requires payment to release earnings",
      "group": "combinations",
      "weight": 0,
      "family": "scam",
      "type": "combination",
      "all_signals": [
        [
          "task_work"
        ],
        [
          "unlock_earnings",
          "crypto_payment",
          "job_fee"
        ]
      ],
      "min_score": 85,
      "sources": [
        "ftc_task"
      ]
    },
    {
      "id": "investment_payment",
      "label": "Guaranteed profits combined with a cryptocurrency payment",
      "group": "combinations",
      "weight": 0,
      "family": "scam",
      "type": "combination",
      "all_signals": [
        [
          "guaranteed_profit"
        ],
        [
          "crypto_payment",
          "unlock_earnings"
        ]
      ],
      "min_score": 85,
      "sources": [
        "ic3_investment"
      ]
    },
    {
      "id": "arrest_payment",
      "label": "Legal threats paired with an unusual payment request",
      "group": "combinations",
      "weight": 0,
      "family": "scam",
      "type": "combination",
      "all_signals": [
        [
          "arrest_threat"
        ],
        [
          "gift_payment",
          "crypto_payment",
          "advance_fee"
        ]
      ],
      "min_score": 85,
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "support_takeover",
      "label": "Computer infection pretext plus remote access or payment",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "virus_claim"
        ],
        [
          "remote_access",
          "gift_payment",
          "support_call"
        ]
      ],
      "min_score": 80,
      "sources": [
        "ftc_tech"
      ]
    },
    {
      "id": "captcha_execution",
      "label": "Human verification asks the user to run system commands",
      "group": "combinations",
      "weight": 0,
      "family": "malware",
      "type": "combination",
      "all_signals": [
        [
          "captcha"
        ],
        [
          "run_command"
        ]
      ],
      "min_score": 90,
      "sources": [
        "ftc_captcha"
      ]
    },
    {
      "id": "delivery_capture",
      "label": "Delivery problem requests a fee or personal details via a link",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "delivery_problem"
        ],
        [
          "delivery_fee",
          "credential_request"
        ],
        [
          "url_present",
          "qr_action"
        ]
      ],
      "min_score": 80,
      "sources": [
        "ftc_sms"
      ]
    },
    {
      "id": "toll_capture",
      "label": "Toll payment demand uses a link and pressure or a fee",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "unpaid_toll"
        ],
        [
          "url_present"
        ],
        [
          "urgency",
          "arrest_threat",
          "advance_fee"
        ]
      ],
      "min_score": 80,
      "sources": [
        "ftc_tolls"
      ]
    },
    {
      "id": "qr_capture",
      "label": "QR-code request paired with account pressure and verification",
      "group": "combinations",
      "weight": 0,
      "family": "phishing",
      "type": "combination",
      "all_signals": [
        [
          "qr_action"
        ],
        [
          "account_warning"
        ],
        [
          "verify_action"
        ]
      ],
      "min_score": 80,
      "sources": [
        "ftc_qr"
      ]
    },
    {
      "id": "job_crypto",
      "label": "Job access requires fees and cryptocurrency",
      "group": "combinations",
      "weight": 0,
      "family": "scam",
      "type": "combination",
      "all_signals": [
        [
          "job_fee"
        ],
        [
          "crypto_payment"
        ]
      ],
      "min_score": 85,
      "sources": [
        "ftc_jobs"
      ]
    },
    {
      "id": "link_invalid",
      "label": "Malformed or ambiguous URL; destination is not verified",
      "weight": 35,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_brand_subdomain",
      "label": "A known brand domain is placed before an unrelated domain",
      "weight": 80,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_brand_login",
      "label": "Brand-like hostname combined with a sign-in or verification path",
      "weight": 80,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_brand_lookalike",
      "label": "Hostname resembles a brand but is outside its listed domains",
      "weight": 45,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_userinfo",
      "label": "Text before @ disguises the actual hostname",
      "weight": 65,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_idn",
      "label": "Internationalized or punycode hostname requires closer inspection",
      "weight": 8,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_confusable",
      "label": "Mixed-script letters make a hostname resemble a known brand",
      "weight": 75,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_shortener",
      "label": "Shortened link; final destination has not been expanded",
      "weight": 10,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_ip",
      "label": "Numeric or local-network hostname; no public-site identity verified",
      "weight": 15,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_http",
      "label": "HTTP does not encrypt the connection",
      "weight": 5,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_download",
      "label": "Link names an executable or script download",
      "weight": 40,
      "family": "malware",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_double_extension",
      "label": "Document-like filename ends with an executable extension",
      "weight": 80,
      "family": "malware",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_secret_query",
      "label": "URL contains a password, code or recovery-secret parameter",
      "weight": 70,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_redirect",
      "label": "URL contains a different embedded destination; no redirect was followed",
      "weight": 10,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_nested_risk",
      "label": "An embedded redirect destination has high-risk indicators",
      "weight": 80,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_scam_lure",
      "label": "URL combines a money-making or prize lure with a payment theme",
      "weight": 65,
      "family": "scam",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ftc_scams"
      ]
    },
    {
      "id": "link_brand_path",
      "label": "Unrecognized host uses brand and sign-in wording in the path",
      "weight": 35,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    },
    {
      "id": "link_obfuscated",
      "label": "URL uses encoded authority characters or unusual numeric addressing",
      "weight": 35,
      "family": "phishing",
      "group": "link_detail",
      "type": "url",
      "sources": [
        "ms_phishing"
      ]
    }
  ],
  "shorteners": [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "cutt.ly",
    "tiny.cc",
    "rb.gy",
    "rebrand.ly"
  ],
  "brands": [
    {
      "name": "PayPal",
      "tokens": [
        "paypal",
        "paypa1",
        "paypai"
      ],
      "domains": [
        "paypal.com"
      ]
    },
    {
      "name": "Microsoft",
      "tokens": [
        "microsoft",
        "micr0soft",
        "rnicrosoft"
      ],
      "domains": [
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "office.com"
      ]
    },
    {
      "name": "Apple",
      "tokens": [
        "apple",
        "app1e"
      ],
      "domains": [
        "apple.com",
        "icloud.com"
      ]
    },
    {
      "name": "Amazon",
      "tokens": [
        "amazon",
        "amaz0n",
        "amazom"
      ],
      "domains": [
        "amazon.com",
        "amazon.co.uk"
      ]
    },
    {
      "name": "Google",
      "tokens": [
        "google",
        "g00gle"
      ],
      "domains": [
        "google.com",
        "accounts.google.com"
      ]
    },
    {
      "name": "Netflix",
      "tokens": [
        "netflix",
        "netf1ix"
      ],
      "domains": [
        "netflix.com"
      ]
    },
    {
      "name": "Chase",
      "tokens": [
        "chase"
      ],
      "domains": [
        "chase.com"
      ]
    },
    {
      "name": "USPS",
      "tokens": [
        "usps"
      ],
      "domains": [
        "usps.com"
      ]
    },
    {
      "name": "UPS",
      "tokens": [
        "ups"
      ],
      "domains": [
        "ups.com"
      ]
    },
    {
      "name": "FedEx",
      "tokens": [
        "fedex"
      ],
      "domains": [
        "fedex.com"
      ]
    },
    {
      "name": "Facebook",
      "tokens": [
        "facebook",
        "faceb00k"
      ],
      "domains": [
        "facebook.com"
      ]
    },
    {
      "name": "Instagram",
      "tokens": [
        "instagram",
        "instagrarn"
      ],
      "domains": [
        "instagram.com"
      ]
    },
    {
      "name": "LinkedIn",
      "tokens": [
        "linkedin",
        "linkedln"
      ],
      "domains": [
        "linkedin.com"
      ]
    }
  ],
  "limitations": [
    "English text and visible URLs only.",
    "Risk scores are heuristic indicators, not calibrated probabilities.",
    "A low score does not establish safety.",
    "No website visits, redirect expansion, attachment execution, OCR, or sender authentication.",
    "Brand domain lists are partial; mismatch is an indicator, not proof.",
    "Sources document tactics; rule weights are authored engineering choices, not agency-endorsed scores.",
    "URL checks inspect strings and local reputation only; the website content, redirects and downloads are not visited."
  ]
}
CG_JSON_END;
