/* ==========================================================================
   ADVANCED AI SECURITY ASSISTANT (v2.0)
   Features:
   - Fuzzy matching with Levenshtein Distance
   - TF-IDF weighted tokenization + Jaccard Similarity
   - ES6 modular architecture with XSS protection
   - Intent disambiguation for low-confidence matches
   - Optimized state management and performance
   ========================================================================== */

(function () {
  'use strict';

  const MAX_QUERY_LENGTH = 500;

  const StringAlgorithms = (() => {
    const levenshteinDistance = (a, b) => {
      if (a.length === 0) return b.length;
      if (b.length === 0) return a.length;

      const matrix = Array(b.length + 1)
        .fill(null)
        .map(() => Array(a.length + 1).fill(0));

      for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
      for (let j = 0; j <= b.length; j++) matrix[j][0] = j;

      for (let j = 1; j <= b.length; j++) {
        for (let i = 1; i <= a.length; i++) {
          const cost = a[i - 1] === b[j - 1] ? 0 : 1;
          matrix[j][i] = Math.min(
            matrix[j][i - 1] + 1,
            matrix[j - 1][i] + 1,
            matrix[j - 1][i - 1] + cost
          );
        }
      }

      return matrix[b.length][a.length];
    };

    const fuzzyScore = (a, b) => {
      const maxLen = Math.max(a.length, b.length);
      if (maxLen === 0) return 1;
      return 1 - levenshteinDistance(a, b) / maxLen;
    };

    const tokenize = (text) => String(text || '')
      .toLowerCase()
      .replace(/[^\w\s@.-]/g, ' ')
      .split(/\s+/)
      .filter((token) => token.length > 0);

    const getTermFrequency = (tokens) => {
      const tf = {};
      tokens.forEach((token) => {
        tf[token] = (tf[token] || 0) + 1;
      });
      return tf;
    };

    const jaccardSimilarity = (tokens1, tokens2) => {
      const set1 = new Set(tokens1);
      const set2 = new Set(tokens2);
      const intersection = [...set1].filter((token) => set2.has(token)).length;
      const union = new Set([...set1, ...set2]).size;
      return union === 0 ? 0 : intersection / union;
    };

    const tfidfSimilarity = (query, text, corpus = []) => {
      const queryTokens = tokenize(query);
      const textTokens = tokenize(text);

      if (queryTokens.length === 0 || textTokens.length === 0) {
        return jaccardSimilarity(queryTokens, textTokens);
      }

      const queryTF = getTermFrequency(queryTokens);
      const textTF = getTermFrequency(textTokens);

      const corpusTokens = corpus.map((doc) => tokenize(doc));
      const allTokens = new Set([...queryTokens, ...textTokens]);
      const idf = {};

      allTokens.forEach((token) => {
        const docsWithToken = corpusTokens.filter((tokens) => tokens.includes(token)).length;
        idf[token] = corpusTokens.length > 0 ? Math.log(corpusTokens.length / (docsWithToken + 1)) + 1 : 1;
      });

      let dotProduct = 0;
      let queryMagnitude = 0;
      let textMagnitude = 0;

      allTokens.forEach((token) => {
        const queryScore = (queryTF[token] || 0) * (idf[token] || 1);
        const textScore = (textTF[token] || 0) * (idf[token] || 1);
        dotProduct += queryScore * textScore;
        queryMagnitude += queryScore ** 2;
        textMagnitude += textScore ** 2;
      });

      const magnitude = Math.sqrt(queryMagnitude * textMagnitude);
      return magnitude === 0 ? 0 : dotProduct / magnitude;
    };

    const normalize = (text) => String(text || '')
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^\w\s@.-]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    return {
      levenshteinDistance,
      fuzzyScore,
      tokenize,
      getTermFrequency,
      jaccardSimilarity,
      tfidfSimilarity,
      normalize,
    };
  })();

  const IntentEngine = (() => {
    const intents = [
      {
        name: 'phishing',
        keywords: ['phishing', 'phish', 'email', 'message', 'recognize', 'recognise', 'red flag'],
        phrases: ['fake email', 'impersonation', 'urgent action required', 'verify account'],
        answer: 'Phishing impersonates a trusted person or organization to steal information. Warning signs: urgent requests, suspicious sender, grammar errors, unexpected attachments, links that don\'t match the sender, and requests to verify credentials. Never click links or download attachments from unexpected emails. Verify the sender through official channels before responding.',
        priority: 1,
      },
      {
        name: 'scam',
        keywords: ['scam', 'fraud', 'lottery', 'prize', 'won', 'fee', 'money', 'gift card', 'romance', 'job offer'],
        phrases: ['advance payment', 'unexpected prize', 'financial gain', 'too good to be true'],
        answer: 'Scam warning signs include unexpected prizes, advance fees, gifts, or financial rewards you did not enter. Legitimate organizations never ask for payment upfront. Never send money, gift cards, or personal details to unknown contacts. Verify any financial opportunity independently through official websites or phone numbers.',
        priority: 1,
      },
      {
        name: 'url safety',
        keywords: ['url', 'link', 'website', 'click', 'shortened', 'domain', 'http'],
        phrases: ['suspicious link', 'unknown website', 'malicious url', 'domain mismatch'],
        answer: 'Treat unexpected URLs as unsafe until verified. Hover over links to inspect the destination (without clicking). Check if the domain matches the sender\'s organization. Avoid shortened URLs from unknown sources—they hide the real destination. Use security tools to check URLs before clicking. When in doubt, navigate to the official website directly by typing the address yourself.',
        priority: 1,
      },
      {
        name: 'passwords',
        keywords: ['password', 'passcode', 'pin', 'credential', 'secure', 'protect'],
        phrases: ['strong password', 'change password', 'password manager', 'password reset'],
        answer: 'Use a unique, long password (16+ characters) for every account and store it in a trusted password manager like Bitwarden, 1Password, or KeePass. Never reuse passwords. Include uppercase, lowercase, numbers, and symbols. Never share passwords or security codes via email or messaging. Never enter your password on unexpected login pages—always navigate to official websites yourself.',
        priority: 1,
      },
      {
        name: 'mfa',
        keywords: ['2fa', 'mfa', 'two factor', 'multi factor', 'authentication', 'authenticator'],
        phrases: ['backup codes', 'authentication app', 'security key', 'one time code'],
        answer: 'Multi-factor authentication (MFA) adds an extra security check after your password. Preferred methods: authenticator apps (Google Authenticator, Authy), hardware security keys (YubiKey), or recovery codes. SMS and email are less secure. Enable MFA on all accounts that matter: email, bank, work, social media. Keep backup codes in a safe place. Never share MFA codes with anyone.',
        priority: 1,
      },
      {
        name: 'attachments',
        keywords: ['attachment', 'file', 'download', 'document', 'malware', 'executable'],
        phrases: ['open attachment', 'file download', 'unexpected file', 'suspicious document'],
        answer: 'Do not open unexpected attachments, especially executable files (.exe, .bat, .cmd) or compressed files (.zip, .rar) from unknown senders. Even if from a known person, verify they intended to send it. Malware can be disguised as documents. Use antivirus software to scan files before opening. Request re-delivery through official channels if unsure.',
        priority: 1,
      },
      {
        name: 'reporting',
        keywords: ['report', 'threat', 'suspicious', 'clicked', 'compromised', 'breach'],
        phrases: ['report phishing', 'security incident', 'account compromised', 'data breach'],
        answer: 'If you suspect a phishing email: (1) Do NOT reply or click more links, (2) Report to your email provider, (3) Report to the organization being impersonated, (4) Forward to abuse@[domain], (5) If you clicked a link: change your password, enable MFA, monitor accounts. If financial info was involved, contact your bank. If identity stolen, consider credit monitoring and fraud alerts.',
        priority: 1,
      },
      {
        name: 'help',
        keywords: ['help', 'hello', 'hi', 'hey', 'question', 'what can you do', 'how does this work'],
        phrases: ['tell me more', 'teach me', 'information', 'guide'],
        answer: 'I\'m your Security Assistant! I can help with: phishing recognition, scam identification, URL safety, password security, multi-factor authentication (MFA), file attachment safety, and threat reporting. Ask me anything like: "How do I recognize phishing?" "What should I do if I clicked a suspicious link?" or "How do I enable 2FA?" I\'m here to keep you safe online.',
        priority: 2,
      },
    ];

    const corpus = intents.map((intent) => intent.answer);

    const scoreIntent = (intent, query, queryTokens) => {
      const keywordText = intent.keywords.join(' ');
      const phraseText = intent.phrases.join(' ');
      const fullText = `${intent.name} ${keywordText} ${phraseText}`;

      let keywordScore = 0;
      intent.keywords.forEach((keyword) => {
        const normalizedKeyword = StringAlgorithms.normalize(keyword);
        const normalizedQuery = StringAlgorithms.normalize(query);

        if (normalizedQuery.includes(normalizedKeyword)) {
          keywordScore += normalizedKeyword.split(' ').length > 1 ? 3 : 1;
        } else {
          const fuzzy = StringAlgorithms.fuzzyScore(normalizedKeyword, normalizedQuery);
          if (fuzzy > 0.7) {
            keywordScore += fuzzy * (normalizedKeyword.split(' ').length > 1 ? 3 : 1);
          }
        }
      });

      let phraseScore = 0;
      intent.phrases.forEach((phrase) => {
        const normalizedPhrase = StringAlgorithms.normalize(phrase);
        const fuzzy = StringAlgorithms.fuzzyScore(normalizedPhrase, query);
        if (fuzzy > 0.6) phraseScore += fuzzy * 2;
      });

      const jaccardScore = StringAlgorithms.jaccardSimilarity(
        queryTokens,
        StringAlgorithms.tokenize(fullText)
      );

      const tfidfScore = StringAlgorithms.tfidfSimilarity(query, intent.answer, corpus);
      const compositeScore = keywordScore * 2.5 + phraseScore * 1.5 + jaccardScore + tfidfScore * 0.5;

      return {
        intentName: intent.name,
        keywordScore,
        phraseScore,
        jaccardScore,
        tfidfScore,
        compositeScore,
        priority: intent.priority,
      };
    };

    const findIntent = (question) => {
      const query = StringAlgorithms.normalize(question).slice(0, MAX_QUERY_LENGTH);
      const queryTokens = StringAlgorithms.tokenize(query);

      if (!query.trim()) {
        return {
          topMatch: intents.find((intent) => intent.name === 'help'),
          alternates: [],
          confidence: 1,
          requiresDisambiguation: false,
        };
      }

      const scores = intents.map((intent) => ({
        intent,
        ...scoreIntent(intent, query, queryTokens),
      }));

      scores.sort((a, b) => b.compositeScore - a.compositeScore);

      const topMatch = scores[0];
      const secondMatch = scores[1];
      const confidence = Math.min(1, topMatch.compositeScore / 15);
      const disambiguationThreshold = 0.3;
      const requiresDisambiguation = confidence < disambiguationThreshold && topMatch.compositeScore < 3 && secondMatch && secondMatch.compositeScore > 0.5;

      return {
        topMatch: topMatch.intent,
        topScore: topMatch.compositeScore,
        alternates: scores.slice(1, 3).map((score) => ({
          intent: score.intent,
          score: score.compositeScore,
        })),
        confidence,
        requiresDisambiguation,
      };
    };

    const answerQuestion = (question) => {
      const result = findIntent(question);

      if (result.requiresDisambiguation && result.alternates.length > 0) {
        const alt1 = result.alternates[0]?.intent?.name || 'help';
        const alt2 = result.alternates[1]?.intent?.name || 'help';
        return `I'm not entirely sure what you're asking about. Did you mean ${alt1} or ${alt2}? Try rephrasing or ask directly about phishing, scams, URLs, passwords, MFA, attachments, or reporting.`;
      }

      if (result.topScore > 0) {
        return result.topMatch.answer;
      }

      return 'I could not match that to a security topic. Ask me about phishing, scams, suspicious URLs, passwords, MFA, attachments, or reporting a threat.';
    };

    return { answerQuestion, findIntent, intents };
  })();

  const ContextualAdvice = (() => {
    const generateAdvice = (score) => {
      const risk = Number(score) || 0;

      if (risk >= 80) {
        return '🚨 CRITICAL RISK: Do NOT click links, open attachments, reply, or share information. Report the message immediately to your email provider and IT department. If financial details were involved, contact your bank at their official number (not from the email).';
      }

      if (risk >= 60) {
        return '⚠️ HIGH RISK: Do not click links, open attachments, or reply. Do not share passwords, codes, or personal information. Report to your email provider and the impersonated organization. Monitor your accounts for unauthorized activity.';
      }

      if (risk >= 30) {
        return '⚡ SUSPICIOUS: Verify the sender independently using official contact details from the organization\'s website. Do NOT use contact information from this message. Hover over links to inspect destinations. Be cautious with attachments and personal information.';
      }

      return 'LOW RISK — NOT VERIFIED: Few configured indicators matched. This does not prove the message or URL is safe. Confirm unexpected requests using a known contact method; never disclose passwords or sign-in codes.';
    };

    return { generateAdvice };
  })();

  const DOMUtils = (() => {
    const escapeHTML = (text) => {
      const div = document.createElement('div');
      div.textContent = String(text || '');
      return div.innerHTML;
    };

    const createMessageElement = (text, sender) => {
      const item = document.createElement('div');
      item.className = `chat-message ${sender}`;
      item.style.wordWrap = 'break-word';
      item.style.overflowWrap = 'break-word';
      item.textContent = String(text || '');
      if (String(text || '').includes('\n')) {
        item.style.whiteSpace = 'pre-wrap';
      }
      return item;
    };

    const autoScroll = (container) => {
      if (container) container.scrollTop = container.scrollHeight;
    };

    const getElement = (id) => document.getElementById(id);

    return { escapeHTML, createMessageElement, autoScroll, getElement };
  })();

  const PerformanceUtils = (() => {
    const debounce = (func, delay) => {
      let timeoutId;
      return function debounced(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
      };
    };

    const throttle = (func, limit) => {
      let inThrottle = false;
      return function throttled(...args) {
        if (!inThrottle) {
          func.apply(this, args);
          inThrottle = true;
          setTimeout(() => {
            inThrottle = false;
          }, limit);
        }
      };
    };

    return { debounce, throttle };
  })();

  class ChatbotUI {
    constructor() {
      this.isOpen = false;
      this.sending = false;
      this.lastAdviceScore = null;
      this.riskScoreObserver = null;
      this.elements = {};
    }

    init() {
      this.elements = {
        box: DOMUtils.getElement('aiChatBox'),
        messages: DOMUtils.getElement('aiChatMessages'),
        input: DOMUtils.getElement('aiChatInput'),
        sendButton: DOMUtils.getElement('aiSendBtn'),
        toggleButton: DOMUtils.getElement('aiToggleBtn'),
        closeButton: DOMUtils.getElement('aiCloseBtn'),
        riskScore: DOMUtils.getElement('riskScore'),
      };

      const required = ['box', 'messages', 'input', 'sendButton', 'toggleButton', 'closeButton'];
      if (!required.every((key) => this.elements[key])) {
        console.warn('ChatbotUI: Required DOM elements not found');
        return;
      }

      this.attachEventListeners();
      this.addMessage('Hi! I am your Security Assistant. Ask about phishing, scams, URL safety, passwords, MFA, attachments, or reporting a threat.', 'assistant');
      this.updateButtonState();
      this.observeRiskScore();
    }

    attachEventListeners() {
      this.elements.toggleButton.addEventListener('click', () => this.toggle(true));
      this.elements.closeButton.addEventListener('click', () => this.toggle(false));
      this.elements.sendButton.addEventListener('click', () => this.send());
      this.elements.input.addEventListener('input', () => this.updateButtonState());
      this.elements.input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
          event.preventDefault();
          this.send();
        }
      });
    }

    updateButtonState() {
      this.elements.sendButton.disabled = this.sending || !this.elements.input.value.trim();
    }

    toggle(open = !this.isOpen) {
      this.isOpen = open;
      this.elements.box.classList.toggle('open', open);
      if (open) this.elements.input.focus();
    }

    addMessage(text, sender = 'assistant') {
      const messageElement = DOMUtils.createMessageElement(text, sender);
      this.elements.messages.appendChild(messageElement);
      DOMUtils.autoScroll(this.elements.messages);
      return messageElement;
    }

    send = PerformanceUtils.debounce(() => {
      if (this.sending) return;

      const question = this.elements.input.value.trim();
      if (!question) return;

      const safeQuestion = question.slice(0, MAX_QUERY_LENGTH);
      this.addMessage(safeQuestion, 'user');
      this.elements.input.value = '';
      this.sending = true;
      this.updateButtonState();

      const typing = this.addMessage('Thinking…', 'assistant');
      window.setTimeout(() => {
        typing.remove();
        this.addMessage(IntentEngine.answerQuestion(safeQuestion), 'assistant');
        this.sending = false;
        this.updateButtonState();
        this.elements.input.focus();

        if (typeof window.logSecurityEvent === 'function') {
          window.logSecurityEvent('AI_CHAT_INTERACTION', { inputLength: safeQuestion.length });
        }
      }, 250);
    }, 100);

    observeRiskScore() {
      if (!this.elements.riskScore) return;

      if (this.riskScoreObserver) {
        this.riskScoreObserver.disconnect();
      }

      const onRiskChange = PerformanceUtils.throttle(() => {
        const scoreText = this.elements.riskScore.textContent.trim();
        const score = Number(scoreText);

        if (!Number.isFinite(score) || this.lastAdviceScore === score) return;

        this.lastAdviceScore = score;
        this.addMessage(ContextualAdvice.generateAdvice(score), 'assistant');

        if (typeof window.logSecurityEvent === 'function') {
          window.logSecurityEvent('AI_CONTEXTUAL_ADVICE', { riskScore: score });
        }
      }, 500);

      this.riskScoreObserver = new MutationObserver(onRiskChange);
      this.riskScoreObserver.observe(this.elements.riskScore, {
        childList: true,
        characterData: true,
        subtree: true,
      });
    }

    reset() {
      if (!this.elements.messages) return;
      if (this.riskScoreObserver) this.riskScoreObserver.disconnect();
      this.elements.messages.replaceChildren();
      this.elements.input.value = '';
      this.sending = false;
      this.lastAdviceScore = null;
      if (this.elements.riskScore) this.elements.riskScore.textContent = '0';
      this.addMessage('Hi! I am your Security Assistant. Ask about phishing, scams, URL safety, passwords, MFA, attachments, or reporting a threat.', 'assistant');
      this.updateButtonState();
      this.toggle(false);
      this.observeRiskScore();
    }

    destroy() {
      if (this.riskScoreObserver) {
        this.riskScoreObserver.disconnect();
        this.riskScoreObserver = null;
      }
      this.elements = {};
    }
  }

  window.AIAssistant = {
    answerQuestion: (question) => IntentEngine.answerQuestion(question),
    contextualAdvice: (score) => ContextualAdvice.generateAdvice(score),
    intents: IntentEngine.intents,
    StringAlgorithms,
    IntentEngine,
    ContextualAdvice,
  };

  window.ChatbotUI = ChatbotUI;

  const chatbot = new ChatbotUI();
  window.resetAssistant = () => chatbot.reset();

  document.addEventListener('DOMContentLoaded', () => {
    chatbot.init();
  }, { once: true });

  window.addEventListener('beforeunload', () => {
    chatbot.destroy();
  });
})();
