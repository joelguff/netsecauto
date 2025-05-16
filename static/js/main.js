// Main JavaScript file for Network Security Automation Tool

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Device Command functionality setup
    setupDeviceCommands();
});

function setupDeviceCommands() {
    // Command dropdown handling
    const commandSelect = document.getElementById('commandSelect');
    const customCommand = document.getElementById('customCommand');
    
    if (commandSelect && customCommand) {
        commandSelect.addEventListener('change', function() {
            if (this.value === 'custom') {
                customCommand.style.display = 'block';
                customCommand.focus();
            } else {
                customCommand.style.display = 'none';
            }
        });
    }
}

// Function to display a flash message
function showAlert(message, type = 'info') {
    const alertContainer = document.createElement('div');
    alertContainer.className = `alert alert-${type} alert-dismissible fade show`;
    alertContainer.role = 'alert';
    
    alertContainer.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    const container = document.querySelector('.container');
    container.insertBefore(alertContainer, container.firstChild);
    
    // Auto dismiss after 5 seconds
    setTimeout(function() {
        const bsAlert = new bootstrap.Alert(alertContainer);
        bsAlert.close();
    }, 5000);
}

// Copy to clipboard functionality
function copyToClipboard(text, button) {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
    
    setTimeout(() => {
        button.innerHTML = originalText;
    }, 2000);
}
