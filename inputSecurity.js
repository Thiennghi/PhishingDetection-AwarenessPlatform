/* ==========================================================================
   INPUT SECURITY MODULE
   Handles input validation, sanitization, length limits, and XSS prevention
   ========================================================================== */

// Configuration for input security constraints
const SecurityConfig = {
  // Maximum character limits for different input fields
  MAX_MESSAGE_LENGTH: 5000,      // Max length for analysis textarea
  MAX_REPORT_LENGTH: 3000,       // Max length for threat report
  MAX_URL_LENGTH: 2048,          // Max length for URLs
  
  // Minimum length validation
  MIN_MESSAGE_LENGTH: 5,         // Minimum characters required
  
  // Pattern definitions for validation
  PATTERNS: {
    // Dangerous script patterns
    SCRIPT_TAGS: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    // Event handlers in HTML
    EVENT_HANDLERS: /on\w+\s*=\s*["'][^"']*["']/gi,
    // HTML tags (for complete sanitization)
    HTML_TAGS: /<[^>]*>/g,
    // Dangerous protocols
    DANGEROUS_PROTOCOLS: /^(javascript|data|vbscript):/i,
  },
  
  // Blacklist of dangerous strings
  DANGEROUS_STRINGS: [
    '<script',
    'javascript:',
    'onerror=',
    'onclick=',
    'onload=',
    'eval(',
  ]
};

/**
 * Main Input Validation & Sanitization Function
 * Performs multiple layers of security checks
 * @param {string} input - The user input to validate
 * @param {string} fieldType - Type of field ('message' or 'report')
 * @returns {object} - { isValid: boolean, sanitized: string, errors: array }
 */
function validateAndSanitizeInput(input, fieldType = 'message') {
  const errors = [];
  let sanitized = input || '';

  // 1. LENGTH VALIDATION
  const maxLength = fieldType === 'report' ? SecurityConfig.MAX_REPORT_LENGTH : SecurityConfig.MAX_MESSAGE_LENGTH;
  
  if (!sanitized || sanitized.trim().length === 0) {
    errors.push('Input cannot be empty');
    return { isValid: false, sanitized: '', errors };
  }

  if (sanitized.length > maxLength) {
    errors.push(`Input exceeds maximum length of ${maxLength} characters (current: ${sanitized.length})`);
    sanitized = sanitized.substring(0, maxLength);
  }

  if (sanitized.trim().length < SecurityConfig.MIN_MESSAGE_LENGTH) {
    errors.push(`Input must be at least ${SecurityConfig.MIN_MESSAGE_LENGTH} characters`);
    return { isValid: false, sanitized: '', errors };
  }

  // 2. XSS PREVENTION - Remove malicious scripts
  if (containsDangerousContent(sanitized)) {
    errors.push('Input contains potentially malicious code and has been sanitized');
    sanitized = sanitizeDangerousContent(sanitized);
  }

  // 3. CHARACTER ENCODING VALIDATION
  if (!isValidUTF8(sanitized)) {
    errors.push('Invalid character encoding detected');
    sanitized = sanitizeInvalidCharacters(sanitized);
  }

  // 4. SPECIAL CHARACTER NORMALIZATION
  sanitized = normalizeSpecialCharacters(sanitized);

  // 5. WHITESPACE NORMALIZATION
  sanitized = sanitized.trim();
  sanitized = sanitized.replace(/\s+/g, ' '); // Replace multiple spaces with single space

  return {
    isValid: errors.length === 0,
    sanitized,
    errors
  };
}

/**
 * Detects if input contains dangerous content
 * @param {string} input - Input to check
 * @returns {boolean} - True if dangerous content found
 */
function containsDangerousContent(input) {
  // Use fresh, non-global regexes for .test(): a /g regex keeps lastIndex between
  // calls, which made detection randomly fail on every second submission.
  if (new RegExp(SecurityConfig.PATTERNS.SCRIPT_TAGS.source, 'i').test(input)) {
    return true;
  }

  if (new RegExp(SecurityConfig.PATTERNS.EVENT_HANDLERS.source, 'i').test(input)) {
    return true;
  }

  // Check for dangerous strings (case-insensitive)
  const lowerInput = input.toLowerCase();
  for (let dangerous of SecurityConfig.DANGEROUS_STRINGS) {
    if (lowerInput.includes(dangerous.toLowerCase())) {
      return true;
    }
  }

  return false;
}

/**
 * Removes dangerous content while preserving text
 * @param {string} input - Input to sanitize
 * @returns {string} - Sanitized string
 */
function sanitizeDangerousContent(input) {
  let sanitized = input;

  // Remove script tags
  sanitized = sanitized.replace(SecurityConfig.PATTERNS.SCRIPT_TAGS, '');

  // Remove event handlers
  sanitized = sanitized.replace(SecurityConfig.PATTERNS.EVENT_HANDLERS, '');

  // Remove HTML tags but keep text content
  sanitized = sanitized.replace(SecurityConfig.PATTERNS.HTML_TAGS, '');

  // HTML encode dangerous characters
  sanitized = encodeHTMLEntities(sanitized);

  return sanitized;
}

/**
 * HTML Encode to prevent injection
 * @param {string} str - String to encode
 * @returns {string} - HTML encoded string
 */
function encodeHTMLEntities(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Checks if string is valid UTF-8
 * @param {string} str - String to validate
 * @returns {boolean} - True if valid UTF-8
 */
function isValidUTF8(str) {
  try {
    return decodeURIComponent(encodeURIComponent(str)) === str;
  } catch (e) {
    return false;
  }
}

/**
 * Removes invalid UTF-8 characters
 * @param {string} str - String to sanitize
 * @returns {string} - Sanitized string
 */
function sanitizeInvalidCharacters(str) {
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * Normalizes special characters to prevent bypass attempts
 * @param {string} str - String to normalize
 * @returns {string} - Normalized string
 */
function normalizeSpecialCharacters(str) {
  // Normalize Unicode characters
  // Keep Unicode/hidden characters until the detector checks obfuscation.
  
  // Remove zero-width characters
  // Matching normalization occurs in detectionEngine.js.
  
  // Remove other potentially dangerous Unicode
  str = str.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
  
  return str;
}

/**
 * Validates email format (for report fields)
 * @param {string} email - Email to validate
 * @returns {boolean} - True if valid email format
 */
function validateEmailFormat(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Rate limiting function to prevent abuse
 * @returns {boolean} - True if request allowed, false if rate limited
 */
function checkRateLimit() {
  const maxRequests = 10;          // Max requests per time window
  const timeWindow = 60 * 1000;    // 60 seconds
  
  const now = Date.now();
  let submissions = [];
  try {
    submissions = JSON.parse(localStorage.getItem('submissions') || '[]');
  } catch (e) {
    submissions = [];
  }
  
  // Filter out old submissions outside time window
  const recentSubmissions = submissions.filter(time => now - time < timeWindow);
  
  if (recentSubmissions.length >= maxRequests) {
    console.warn('Rate limit exceeded');
    return false;
  }
  
  // Add current submission
  recentSubmissions.push(now);
  try {
    localStorage.setItem('submissions', JSON.stringify(recentSubmissions));
  } catch (e) {
    // storage unavailable: skip client-side limiting, the server still enforces limits
  }

  return true;
}

/**
 * Display validation errors to user (safe: built with textContent, never innerHTML)
 * @param {array} errors - Array of error messages
 * @param {string} formId - Form the errors belong to (default: the analysis form)
 */
function displayValidationErrors(errors, formId = 'detectionForm') {
  if (!errors || errors.length === 0) return;

  const form = document.getElementById(formId);
  if (!form) return;

  const containerId = formId === 'detectionForm' ? 'validationErrors' : 'validationErrors-' + formId;
  let errorContainer = document.getElementById(containerId);

  if (!errorContainer) {
    errorContainer = document.createElement('div');
    errorContainer.id = containerId;
    errorContainer.className = 'validation-errors alert alert-danger';
    errorContainer.setAttribute('role', 'alert');
    errorContainer.style.cssText = `
      background-color: rgba(239, 68, 68, 0.1);
      border: 1px solid #ef4444;
      color: #ef4444;
      padding: 1rem;
      border-radius: 6px;
      margin-bottom: 1rem;
    `;
    form.parentNode.insertBefore(errorContainer, form);
  }

  errorContainer.textContent = '';

  const title = document.createElement('strong');
  title.textContent = 'Validation Error:';
  errorContainer.appendChild(title);

  const list = document.createElement('ul');
  errors.forEach(err => {
    const item = document.createElement('li');
    item.textContent = String(err);
    list.appendChild(item);
  });
  errorContainer.appendChild(list);

  errorContainer.style.display = 'block';
}

/**
 * Clear every validation error box
 */
function clearValidationErrors() {
  document.querySelectorAll('.validation-errors').forEach(box => {
    box.style.display = 'none';
  });
}

/**
 * Log security events for monitoring
 * @param {string} eventType - Type of security event
 * @param {object} details - Event details
 */
function logSecurityEvent(eventType, details) {
  const event = {
    timestamp: new Date().toISOString(),
    type: eventType,
    details: details
  };

  // Store in localStorage for audit trail (max 50 events)
  try {
    const logs = JSON.parse(localStorage.getItem('securityLogs') || '[]');
    logs.push(event);

    if (logs.length > 50) {
      logs.shift(); // Remove oldest event
    }

    localStorage.setItem('securityLogs', JSON.stringify(logs));
  } catch (e) {
    // storage unavailable: console logging below still works
  }

  // Log to console in development
  console.log('[SECURITY EVENT]', event);
}

/**
 * Sanitize input for display in HTML
 * @param {string} text - Text to sanitize for display
 * @returns {string} - HTML-safe string
 */
function sanitizeForDisplay(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
