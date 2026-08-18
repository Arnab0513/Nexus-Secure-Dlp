document.addEventListener('DOMContentLoaded', () => {
    
    // UI Elements
    const btnBrowse = document.getElementById('btn-browse');
    const btnDecrypt = document.getElementById('btn-decrypt');
    const btnTogglePassword = document.getElementById('btn-toggle-password');
    const btnRestart = document.getElementById('btn-restart');
    
    const authTokenInput = document.getElementById('auth-token');
    const authErrorMsg = document.getElementById('auth-error');
    
    const fileDetails = document.getElementById('file-details');
    const fileName = document.getElementById('file-name');
    const fileSize = document.getElementById('file-size');
    const fileDept = document.getElementById('file-dept');
    
    const step1Card = document.getElementById('step-1-card');
    const step2Card = document.getElementById('step-2-card');
    const step1Indicator = document.getElementById('step-1-indicator');
    const step2Indicator = document.getElementById('step-2-indicator');
    const progressFill = document.getElementById('progress-fill');
    
    const successOverlay = document.getElementById('success-overlay');
    const successMessage = document.getElementById('success-message');
    
    let isFileSelected = false;
    let selectedFilePath = null;

    // Browse Button
    btnBrowse.addEventListener('click', async () => {
        try {
            // Call Python backend
            const fileInfo = await window.pywebview.api.browse_file();
            if (fileInfo) {
                handleFileSelected(fileInfo);
            }
        } catch (error) {
            console.error("Failed to browse:", error);
        }
    });

    const btnChangeFile = document.getElementById('btn-change-file');
    if (btnChangeFile) {
        btnChangeFile.addEventListener('click', async () => {
            try {
                const fileInfo = await window.pywebview.api.browse_file();
                if (fileInfo) {
                    handleFileSelected(fileInfo);
                }
            } catch (error) {
                console.error("Failed to browse:", error);
            }
        });
    }

    // Toggle Password Visibility
    btnTogglePassword.addEventListener('click', () => {
        const type = authTokenInput.getAttribute('type') === 'password' ? 'text' : 'password';
        authTokenInput.setAttribute('type', type);
        
        // Change icon based on state
        if (type === 'text') {
            btnTogglePassword.innerHTML = `
                <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                    <line x1="1" y1="1" x2="23" y2="23"></line>
                </svg>`;
        } else {
            btnTogglePassword.innerHTML = `
                <svg class="eye-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                </svg>`;
        }
    });

    // Password Input Validation
    authTokenInput.addEventListener('input', () => {
        authErrorMsg.textContent = '';
        authTokenInput.classList.remove('error');
        if (authTokenInput.value.trim().length > 0) {
            btnDecrypt.disabled = false;
        } else {
            btnDecrypt.disabled = true;
        }
    });

    // Decrypt Button
    btnDecrypt.addEventListener('click', async () => {
        const token = authTokenInput.value;
        if (!token) return;

        // UI Loading State
        btnDecrypt.disabled = true;
        btnDecrypt.querySelector('.btn-text').style.display = 'none';
        btnDecrypt.querySelector('.btn-icon').style.display = 'none';
        btnDecrypt.querySelector('.spinner').style.display = 'block';

        try {
            const result = await window.pywebview.api.decrypt_file(token);
            
            // Revert Loading State
            btnDecrypt.querySelector('.btn-text').style.display = 'block';
            btnDecrypt.querySelector('.btn-icon').style.display = 'block';
            btnDecrypt.querySelector('.spinner').style.display = 'none';
            btnDecrypt.disabled = false;

            if (result.success) {
                // Show Success
                successMessage.textContent = result.message;
                successOverlay.style.display = 'flex';
                
                // Update Step Indicator
                step2Indicator.classList.add('completed');
                progressFill.style.width = '100%';
            } else {
                // Show Error
                authErrorMsg.textContent = result.error;
                authTokenInput.classList.add('error');
            }
        } catch (error) {
            // Revert Loading State
            btnDecrypt.querySelector('.btn-text').style.display = 'block';
            btnDecrypt.querySelector('.btn-icon').style.display = 'block';
            btnDecrypt.querySelector('.spinner').style.display = 'none';
            btnDecrypt.disabled = false;
            
            authErrorMsg.textContent = "An internal error occurred.";
            authTokenInput.classList.add('error');
        }
    });

    // Restart Button
    btnRestart.addEventListener('click', () => {
        successOverlay.style.display = 'none';
        resetUI();
    });

    // Global function to receive file from Python (e.g. IPC double click)
    window.handleFileSelected = function(fileInfo) {
        if (!fileInfo) return;
        
        isFileSelected = true;
        
        // Update UI with file details
        fileName.textContent = fileInfo.filename;
        fileSize.textContent = fileInfo.size;
        fileDept.textContent = `Dept: ${fileInfo.department}`;
        
        btnBrowse.style.display = 'none';
        fileDetails.style.display = 'flex';
        
        // Enable Step 2
        step2Card.classList.remove('disabled');
        authTokenInput.disabled = false;
        
        // Update Step Indicators
        step1Indicator.classList.add('completed');
        step1Indicator.classList.remove('active');
        step2Indicator.classList.add('active');
        progressFill.style.width = '50%';
        
        // Focus password input
        setTimeout(() => authTokenInput.focus(), 100);
    };

    function resetUI() {
        isFileSelected = false;
        
        btnBrowse.style.display = 'inline-flex';
        fileDetails.style.display = 'none';
        
        step2Card.classList.add('disabled');
        authTokenInput.disabled = true;
        authTokenInput.value = '';
        authTokenInput.classList.remove('error');
        authErrorMsg.textContent = '';
        btnDecrypt.disabled = true;
        
        step1Indicator.classList.remove('completed');
        step1Indicator.classList.add('active');
        step2Indicator.classList.remove('active');
        step2Indicator.classList.remove('completed');
        progressFill.style.width = '0%';
    }
});
