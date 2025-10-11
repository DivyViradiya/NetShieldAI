// Ensure this script is loaded after the HTML elements are available
document.addEventListener('DOMContentLoaded', function() {
    // Get references to HTML elements
    const reportFile = document.getElementById('reportFile');
    const llmModel = document.getElementById('llmModel');
    const uploadButton = document.getElementById('uploadButton');
    const uploadStatus = document.getElementById('uploadStatus');
    const reportSummary = document.getElementById('reportSummary'); // Still need this for initial empty state
    const chatBox = document.getElementById('chatBox');
    const userMessageInput = document.getElementById('userMessage');
    const sendMessageButton = document.getElementById('sendMessage');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const clearChatButton = document.getElementById('clearChatButton');

    // Custom Modal Elements
    const customModal = document.getElementById('customModal');
    const modalMessage = document.getElementById('modalMessage');
    const modalButtons = document.getElementById('modalButtons');
    const closeButton = document.querySelector('#customModal .close-button');

    // Base URL for Flask chatbot blueprint (as defined in app.py)
    const FLASK_CHATBOT_BASE_URL = '/chatbot'; 

    // Function to show the custom modal
    function showModal(message, type = 'alert', onConfirm = null) {
        modalMessage.textContent = message;
        modalButtons.innerHTML = ''; // Clear previous buttons

        if (type === 'alert') {
            const okButton = document.createElement('button');
            okButton.textContent = 'OK';
            okButton.className = 'bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg transition duration-300';
            okButton.onclick = () => customModal.style.display = 'none';
            modalButtons.appendChild(okButton);
        } else if (type === 'confirm') {
            const confirmBtn = document.createElement('button');
            confirmBtn.textContent = 'Confirm';
            confirmBtn.className = 'bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg transition duration-300';
            confirmBtn.onclick = () => {
                customModal.style.display = 'none';
                if (onConfirm) onConfirm();
            };
            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = 'Cancel';
            cancelBtn.className = 'bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg transition duration-300';
            cancelBtn.onclick = () => customModal.style.display = 'none';
            modalButtons.appendChild(confirmBtn);
            modalButtons.appendChild(cancelBtn);
        }
        customModal.style.display = 'flex'; // Use flex to center content
    }

    // Close modal when close button is clicked
    closeButton.onclick = () => customModal.style.display = 'none';

    // Close modal when clicking outside of it
    window.onclick = (event) => {
        if (event.target == customModal) {
            customModal.style.display = 'none';
        }
    };

    // Function to convert basic Markdown to HTML
    function markdownToHtml(markdownText) {
        let html = markdownText;

        // Convert bold text (**) - must be before italic to prevent issues with single asterisks
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        // Convert italic text (*)
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

        // Convert headers (H1, H2, H3, H4)
        // Order matters: H4, H3, H2, H1
        html = html.replace(/^#### (.*$)/gm, '<h4>$1</h4>');
        html = html.replace(/^### (.*$)/gm, '<h3>$1</h3>');
        html = html.replace(/^## (.*$)/gm, '<h2>$1</h2>');
        html = html.replace(/^# (.*$)/gm, '<h1>$1</h1>');

        // Convert unordered lists (-)
        // This regex looks for lines starting with '-' followed by a space,
        // and captures the content. It then wraps them in <li> tags.
        // After that, it looks for sequences of <li> tags and wraps them in <ul>.
        html = html.replace(/^- (.*$)/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*?<\/li>(\s*<li>.*?<\/li>)*)/gs, '<ul>$1</ul>');


        // Convert ordered lists (1.)
        // Similar to unordered lists, but for numbered lists.
        html = html.replace(/^\d+\. (.*$)/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*?<\/li>(\s*<li>.*?<\/li>)*)/gs, '<ol>$1</ol>');
        
        // Convert double newlines to paragraphs, but avoid converting lines that are already part of block elements
        // This is a more robust way to handle paragraphs.
        // It splits the text by double newlines, then processes each block.
        // If a block doesn't start with an HTML tag, it wraps it in a paragraph.
        html = html.split('\n\n').map(block => {
            if (block.trim() === '') {
                return '';
            }
            // Check if the block already starts with an HTML tag (h1-h4, ul, ol, li, p)
            // This prevents wrapping already formatted blocks in <p> tags
            if (block.match(/^(<h[1-4]>|<ul|<ol|<li|<p>)/i)) {
                return block;
            }
            return `<p>${block.trim()}</p>`;
        }).join('');

        // Replace single newlines within paragraphs with <br> for line breaks
        // This should be done AFTER block-level elements are handled
        html = html.replace(/<p>(.*?)<\/p>/gs, (match, content) => {
            return `<p>${content.replace(/\n/g, '<br>')}</p>`;
        });

        return html;
    }


    // Function to append messages to the chat box
    function appendMessage(sender, message, isMarkdown = false) { // Added isMarkdown parameter
        const messageElement = document.createElement('div');
        messageElement.classList.add('chat-message');
        if (sender === 'user') {
            messageElement.classList.add('user-message');
            messageElement.classList.add('self-end'); // Align to right
            messageElement.textContent = message; // User messages are plain text
        } else {
            messageElement.classList.add('ai-message');
            messageElement.classList.add('self-start'); // Align to left
            if (isMarkdown) { // Conditionally render Markdown
                messageElement.innerHTML = markdownToHtml(message); 
            } else {
                messageElement.textContent = message; 
            }
        }
        chatBox.appendChild(messageElement);
        // Scroll to the bottom of the chat box
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    // Event listener for the Upload button
    uploadButton.addEventListener('click', async () => {
        const file = reportFile.files[0];
        const llmMode = llmModel.value;

        if (!file) {
            showModal('Please select a PDF file to upload.', 'alert');
            return;
        }

        if (file.type !== 'application/pdf') {
            showModal('Invalid file type. Please upload a PDF file.', 'alert');
            return;
        }

        uploadStatus.textContent = 'Uploading and processing report...';
        uploadButton.disabled = true;
        loadingIndicator.classList.remove('hidden'); // Show loading indicator

        const formData = new FormData();
        formData.append('report_file', file);
        formData.append('llm_mode', llmMode); // Append selected LLM mode

        try {
            const response = await fetch(`${FLASK_CHATBOT_BASE_URL}/upload_report`, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok) {
                uploadStatus.textContent = 'Report processed successfully!';
                // Clear the chat box and add the summary as the first AI message
                chatBox.innerHTML = ''; // Clear existing messages
                // Pass true for isMarkdown to render the summary with Markdown
                appendMessage('ai', result.message, true); 
                appendMessage('ai', 'How can I help you with this report?'); // Follow-up message
                // Also clear the reportSummary div on the left panel
                reportSummary.innerHTML = `<h3 class="font-semibold text-blue-900 mb-2">Report Summary:</h3><p>Report summary moved to chat interface.</p>`;

            } else {
                uploadStatus.textContent = `Error: ${result.error || 'Unknown error'}`;
                showModal(`Error uploading report: ${result.error || 'Unknown error'}`, 'alert');
                reportSummary.innerHTML = `<h3 class="font-semibold text-blue-900 mb-2">Report Summary:</h3><p>Failed to load summary.</p>`;
            }
        } catch (error) {
            console.error('Error during upload:', error);
            uploadStatus.textContent = 'Network error or server unreachable.';
            showModal('Network error or server unreachable. Please check your connection and try again.', 'alert');
            reportSummary.innerHTML = `<h3 class="font-semibold text-blue-900 mb-2">Report Summary:</h3><p>Failed to load summary due to network error.</p>`;
        } finally {
            uploadButton.disabled = false;
            loadingIndicator.classList.add('hidden'); // Hide loading indicator
        }
    });

    // Function to send a chat message
    async function sendChatMessage() {
        const userMessage = userMessageInput.value.trim();
        if (userMessage === '') {
            showModal('Please enter a message.', 'alert');
            return;
        }

        // Check if the chatBox currently contains the welcome message.
        // This assumes the welcome message is the *only* content initially
        // or is uniquely identified by the 'welcome-section' class.
        if (chatBox.querySelector('.welcome-section')) {
            chatBox.innerHTML = ''; // Clear the welcome message.
        }

        appendMessage('user', userMessage);
        userMessageInput.value = ''; // Clear input field
        sendMessageButton.disabled = true;
        loadingIndicator.classList.remove('hidden'); // Show loading indicator

        try {
            const response = await fetch(`${FLASK_CHATBOT_BASE_URL}/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: userMessage })
            });

            const result = await response.json();

            if (response.ok) {
                // Pass true for isMarkdown to render AI responses with Markdown
                appendMessage('ai', result.response, true);
            } else {
                appendMessage('ai', `Error: ${result.error || 'Unknown error'}`);
                showModal(`Error during chat: ${result.error || 'Unknown error'}`, 'alert');
            }
        } catch (error) {
            console.error('Error during chat:', error);
            appendMessage('ai', 'Network error or server unreachable.');
            showModal('Network error or server unreachable. Please check your connection and try again.', 'alert');
        } finally {
            sendMessageButton.disabled = false;
            loadingIndicator.classList.add('hidden'); // Hide loading indicator
        }
    }

    // Event listener for the Send Message button
    sendMessageButton.addEventListener('click', sendChatMessage);

    // Event listener for Enter key in the message input
    userMessageInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault(); // Prevent default form submission
            sendChatMessage();
        }
    });

    // Event listener for Clear Chat & Report button
    clearChatButton.addEventListener('click', () => {
        showModal('Are you sure you want to clear the chat and report context? This action cannot be undone.', 'confirm', async () => {
            // User confirmed, proceed with clearing
            uploadStatus.textContent = 'Clearing chat and report...';
            clearChatButton.disabled = true;
            loadingIndicator.classList.remove('hidden');

            try {
                const response = await fetch(`${FLASK_CHATBOT_BASE_URL}/clear_chat`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({}) // Empty body for clear_chat
                });

                const result = await response.json();

                if (response.ok) {
                    uploadStatus.textContent = 'Chat and report cleared successfully!';
                    reportSummary.innerHTML = `<h3 class="font-semibold text-blue-900 mb-2">Report Summary:</h3><p>Upload a PDF report to see its summary here.</p>`;
                    chatBox.innerHTML = '<div class="chat-message ai-message">Hello! Upload a security report to get started.</div>'; // Reset chat
                    showModal('Chat and report context cleared.', 'alert');
                } else {
                    uploadStatus.textContent = `Error: ${result.message || 'Unknown error'}`;
                    showModal(`Error clearing chat: ${result.message || 'Unknown error'}`, 'alert');
                }
            } catch (error) {
                console.error('Error during clear chat:', error);
                uploadStatus.textContent = 'Network error or server unreachable during clear chat.';
                showModal('Network error or server unreachable. Please check your connection and try again.', 'alert');
            } finally {
                clearChatButton.disabled = false;
                loadingIndicator.classList.add('hidden');
            }
        });
    });
});
