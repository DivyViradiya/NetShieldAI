document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('file')
  const fileNameDisplay = document.getElementById('file-name-display')
  const uploadButton = document.getElementById('upload-button')
  const uploadStatus = document.getElementById('upload-status')
  const llmSelector = document.getElementById('llm_mode_selector')
  const chatHistory = document.getElementById('chat-history')
  const messagesContainer = document.getElementById('messages-container')
  const welcomeState = document.getElementById('welcome-state')
  const typingIndicator = document.getElementById('typing-indicator')
  const userInput = document.getElementById('user-input')
  const sendBtn = document.getElementById('send-btn')
  const resetBtn = document.getElementById('reset-session-btn')
  const contextIndicator = document.getElementById('context-indicator')
  const suggestionGrid = document.getElementById('suggestion-grid') // New reference
  
  let isProcessing = false
  let currentSuggestionIndex = 0 // Tracks the current set of suggestions

  // --- Question Bank for Rotation ---
  const suggestionGroups = [
    [
      // Group 1
      { type: 'General Query', text: 'What are the top 3 critical vulnerabilities in 2025?', iconColor: 'blue-400', color: 'blue' },
      { type: 'Concept', text: 'Explain remediation strategies for SQL Injection.', iconColor: 'emerald-400', color: 'emerald' }
    ],
    [
      // Group 2
      { type: 'General Query', text: 'How does a Man-in-the-Middle attack work?', iconColor: 'blue-400', color: 'blue' },
      { type: 'Concept', text: 'Outline the steps for a secure password policy.', iconColor: 'emerald-400', color: 'emerald' }
    ],
    [
      // Group 3
      { type: 'General Query', text: 'What is the purpose of a Security Information and Event Management (SIEM) system?', iconColor: 'blue-400', color: 'blue' },
      { type: 'Concept', text: 'Summarize the Zero Trust security model.', iconColor: 'emerald-400', color: 'emerald' }
    ]
    [
    // Group 4
    { type: 'General Query', text: 'What is the difference between encryption and hashing?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Describe a typical incident response plan lifecycle.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 5
    { type: 'General Query', text: 'What is phishing and how can it be prevented?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Provide a checklist for hardening an Ubuntu server.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 6
    { type: 'General Query', text: 'How can I secure a web application against Cross-Site Scripting (XSS)?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Explain the principle of least privilege (PoLP) in detail.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 7
    { type: 'General Query', text: 'What is the typical cost of a ransomware attack in 2024?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Describe the main components of a security awareness training program.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 8
    { type: 'General Query', text: 'How do you perform a basic port scan using Nmap?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'What is the difference between a vulnerability scan and a penetration test?', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 9
    { type: 'General Query', text: 'What are the risks associated with using default credentials?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Explain what an API gateway is and how it improves security.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 10
    { type: 'General Query', text: 'List the primary steps for securing a cloud environment (AWS/Azure).', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Summarize the OWASP Top 10 categories.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 11
    { type: 'General Query', text: 'What role does AI play in modern threat detection?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Define two-factor authentication (2FA) and its variants.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 12
    { type: 'General Query', text: 'What is the primary objective of a Denial of Service (DoS) attack?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'How does network segmentation improve overall security?', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 13
    { type: 'General Query', text: 'Which common programming languages are most prone to buffer overflow attacks?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Describe the function of a Web Application Firewall (WAF).', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 14
    { type: 'General Query', text: 'What are the common indicators of compromise (IoCs)?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Explain the difference between a stream cipher and a block cipher.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 15
    { type: 'General Query', text: 'How can certificate pinning prevent Man-in-the-Middle attacks?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Outline the steps for secure code review in the SDLC.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 16
    { type: 'General Query', text: 'What are the critical risks of third-party software dependencies?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Define the concept of **Data Loss Prevention (DLP)**.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 17
    { type: 'General Query', text: 'What security challenges are unique to the Internet of Things (IoT)?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Explain how hashing is used to ensure data integrity.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 18
    { type: 'General Query', text: 'What methods are used for network intrusion detection?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Describe the main sections of a standardized vulnerability report.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 19
    { type: 'General Query', text: 'What are the current trends in supply chain attacks?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Explain the role of **Transport Layer Security (TLS)** in web communication.', iconColor: 'emerald-400', color: 'emerald' }
  ],
  [
    // Group 20
    { type: 'General Query', text: 'How often should security patches be applied to critical systems?', iconColor: 'blue-400', color: 'blue' },
    { type: 'Concept', text: 'Summarize the steps involved in forensic analysis after a breach.', iconColor: 'emerald-400', color: 'emerald' }
  ]
];
  
  function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight
  }

  // Function to create and inject new suggestion buttons (using DOM for linter-friendliness)
  function updateSuggestions() {
    const suggestions = suggestionGroups[currentSuggestionIndex % suggestionGroups.length]
    suggestionGrid.innerHTML = '' // Clear existing buttons

    suggestions.forEach(suggestion => {
      const button = document.createElement('button')
      button.className = `suggestion-btn group bg-slate-900/50 hover:bg-slate-800 border border-slate-800 hover:border-${suggestion.color}-500/50 p-4 rounded-xl text-left transition-all duration-300`
      
      const headerDiv = document.createElement('div')
      headerDiv.className = 'flex items-center gap-2 mb-1'

      const iconSpan = document.createElement('span')
      iconSpan.className = `material-symbols-outlined text-${suggestion.iconColor} text-sm`
      iconSpan.textContent = suggestion.type === 'Concept' ? 'school' : 'psychology'
      
      const typeSpan = document.createElement('span')
      typeSpan.className = `text-xs font-bold text-${suggestion.iconColor} uppercase`
      typeSpan.textContent = suggestion.type

      headerDiv.appendChild(iconSpan)
      headerDiv.appendChild(typeSpan)
      
      const textSpan = document.createElement('span')
      textSpan.className = 'text-slate-300 text-sm group-hover:text-white'
      textSpan.textContent = suggestion.text

      button.appendChild(headerDiv)
      button.appendChild(textSpan)

      // Re-apply event listener to the new button
      button.addEventListener('click', () => {
        if (textSpan) {
          userInput.value = textSpan.textContent
          sendMessage()
        }
      })
      suggestionGrid.appendChild(button)
    })
    
    currentSuggestionIndex++
  }

  // Updated function to create bubbles WITHOUT icons
  function addMessage(role, text) {
    if (!welcomeState.classList.contains('hidden')) {
      welcomeState.classList.add('hidden')
      welcomeState.style.display = 'none'
    }

    const msgRow = document.createElement('div')
    msgRow.className = `msg-row ${role} animate-slide-up`

    const content = document.createElement('div')
    content.className = 'msg-content'

    if (role === 'ai') {
      content.classList.add('markdown-body')
      content.innerHTML = marked.parse(text)
    } else {
      content.textContent = text
    }

    msgRow.appendChild(content)
    chatHistory.appendChild(msgRow)
    scrollToBottom()
  }

  // --- Logic for Context Switching ---
  function updateContextUI(mode, filename = null) {
    const iconDiv = contextIndicator.querySelector('div:first-child')
    const titleDiv = contextIndicator.querySelector('div:last-child div:first-child')
    const subtitleDiv = contextIndicator.querySelector('div:last-child div:last-child')
    const iconSpan = iconDiv.querySelector('span')

    if (mode === 'report') {
      contextIndicator.className = 'bg-emerald-900/20 border border-emerald-800/50 rounded-xl p-3 flex items-center gap-3 transition-all duration-300'
      iconDiv.className = 'w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400'
      iconSpan.textContent = 'description'
      titleDiv.textContent = 'Report Active'
      titleDiv.className = 'text-sm font-semibold text-emerald-200'
      subtitleDiv.textContent = filename || 'PDF Analysis'
      subtitleDiv.className = 'text-[10px] text-emerald-400 truncate max-w-[150px]'
    } else {
      contextIndicator.className = 'bg-slate-800/50 border border-slate-700 rounded-xl p-3 flex items-center gap-3 transition-all duration-300'
      iconDiv.className = 'w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400'
      iconSpan.textContent = 'public'
      titleDiv.textContent = 'General Mode'
      titleDiv.className = 'text-sm font-semibold text-slate-200'
      subtitleDiv.textContent = 'External Knowledge Base'
      subtitleDiv.className = 'text-[10px] text-slate-400'
    }
  }

  // --- Event Listeners (Manual Upload) ---
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0]
    if (file) {
      fileNameDisplay.textContent = file.name
      fileNameDisplay.className = 'text-xs text-white font-medium truncate w-full px-2'
    } else {
      fileNameDisplay.textContent = 'Drop PDF here or click'
      fileNameDisplay.className = 'text-xs text-slate-300 font-medium truncate w-full px-2'
    }
  })

  uploadButton.addEventListener('click', async () => {
    const file = fileInput.files[0]
    if (!file) {
      alert('Please select a file first.')
      return
    }

    uploadStatus.classList.remove('hidden', 'text-red-400', 'text-green-400')
    uploadStatus.className = 'text-center text-[10px] text-blue-400 mt-2 animate-pulse'
    uploadStatus.textContent = 'Processing PDF...'
    uploadButton.disabled = true
    uploadButton.classList.add('opacity-50', 'cursor-not-allowed')

    const formData = new FormData()
    formData.append('file', file)
    formData.append('llm_mode', llmSelector.value)

    try {
      const response = await fetch('/chatbot/upload_report', {
        method: 'POST',
        body: formData
      })
      const data = await response.json()

      if (response.ok && !data.error) {
        uploadStatus.className = 'text-center text-[10px] text-green-400 mt-2'
        uploadStatus.textContent = 'Ready'
        updateContextUI('report', file.name)

        chatHistory.innerHTML = ''
        addMessage('ai', data.message || 'I have analyzed your report. Here is the summary:\n\n' + (data.summary || ''))
      } else {
        throw new Error(data.error || 'Upload failed')
      }
    } catch (err) {
      uploadStatus.className = 'text-center text-[10px] text-red-400 mt-2'
      uploadStatus.textContent = 'Error: ' + err.message
    } finally {
      uploadButton.disabled = false
      uploadButton.classList.remove('opacity-50', 'cursor-not-allowed')
    }
  })

  // --- Event Listeners (Chat & Reset) ---
  async function sendMessage() {
    const text = userInput.value.trim()
    if (!text || isProcessing) return

    userInput.value = ''
    addMessage('user', text)
    isProcessing = true
    typingIndicator.classList.remove('hidden')
    scrollToBottom()

    try {
      const response = await fetch('/chatbot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text })
      })
      const data = await response.json()

      typingIndicator.classList.add('hidden')

      if (data.response) {
        addMessage('ai', data.response)
        // Rotate suggestions after a successful message
        if (welcomeState.classList.contains('hidden') === false) { 
            // Re-check welcome state visibility to ensure we don't accidentally update 
            // suggestions after the chat has started, if that was the intended behavior.
            // If you want it to rotate *after* every message (even when the welcome state is hidden),
            // remove the surrounding if statement. I'll keep it here assuming you only want
            // the rotation when the user is forced back to the welcome state.
            updateSuggestions() 
        }
      } else {
        addMessage('ai', 'I encountered an error or received an empty response.')
      }
    } catch (err) {
      typingIndicator.classList.add('hidden')
      addMessage('ai', 'Error connecting to server. Please check your connection.')
      console.error(err)
    } finally {
      isProcessing = false
    }
  }

  sendBtn.addEventListener('click', sendMessage)
  userInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendMessage()
  })

  resetBtn.addEventListener('click', async () => {
    if (confirm('Are you sure? This will clear the current chat context.')) {
      await fetch('/chatbot/clear_chat', { method: 'POST' })
      chatHistory.innerHTML = ''
      welcomeState.classList.remove('hidden')
      welcomeState.style.display = 'flex'
      updateContextUI('general')
      fileInput.value = ''
      fileNameDisplay.textContent = 'Drop PDF here or click'
      fileNameDisplay.className = 'text-xs text-slate-300 font-medium truncate w-full px-2'
      uploadStatus.classList.add('hidden')
      updateSuggestions() // Re-run suggestion update on reset

      window.history.pushState({}, document.title, '/chatbot')
    }
  })

  // 🚨 NOTE: We remove the suggestion-btn listener block here because 
  // the listeners are now attached dynamically inside updateSuggestions()

  // Function to check URL parameters on page load
  function checkUrlForAnalysis() {
    const params = new URLSearchParams(window.location.search)
    const mode = params.get('mode')
    const summary = params.get('summary')
    const filename = params.get('filename')

    if (mode && summary) {
      const decodedSummary = decodeURIComponent(summary)

      const contextName = filename ? filename : `${mode.toUpperCase()} Scan Analysis`
      updateContextUI('report', contextName)

      addMessage('ai', decodedSummary)

      window.history.replaceState({}, document.title, '/chatbot')
    } else {
       // Run the suggestion update on clean initial load
       updateSuggestions()
    }
  }

  // Execute the URL check and initial suggestion load on initialization
  checkUrlForAnalysis()
})