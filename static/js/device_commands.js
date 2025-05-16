// Enhanced device command execution functionality

document.addEventListener('DOMContentLoaded', function() {
    // Setup execute command button
    const executeBtn = document.getElementById('executeCommand');
    if (executeBtn) {
        executeBtn.addEventListener('click', function() {
            const deviceId = this.getAttribute('data-device-id');
            const commandSelect = document.getElementById('commandSelect');
            const customCommand = document.getElementById('customCommand');
            let command;
            
            if (commandSelect.value === 'custom') {
                command = customCommand.value.trim();
                if (!command) {
                    showAlert('Please enter a command', 'warning');
                    return;
                }
            } else {
                command = commandSelect.value;
            }
            
            // Show loading indicator
            const outputCard = document.getElementById('commandOutputCard');
            const outputElement = document.getElementById('commandOutput');
            outputCard.style.display = 'block';
            outputElement.innerHTML = '<div class="text-center my-3"><div class="spinner-border text-light" role="status"></div><p class="mt-2">Executing command...</p></div>';
            
            // Send the command to the server
            fetch(`/devices/${deviceId}/connect`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `command=${encodeURIComponent(command)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Update the command title and timestamp
                    document.getElementById('commandTitle').textContent = `Command: ${command}`;
                    document.getElementById('commandTimestamp').textContent = data.timestamp;
                    
                    // Update the output
                    outputElement.innerHTML = data.output;
                    
                    // Add copy button
                    const copyBtn = document.createElement('button');
                    copyBtn.className = 'btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2';
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
                    copyBtn.onclick = function() {
                        copyToClipboard(data.output, this);
                    };
                    
                    const outputContainer = outputElement.parentElement;
                    if (!outputContainer.querySelector('.btn-outline-light')) {
                        outputContainer.style.position = 'relative';
                        outputContainer.appendChild(copyBtn);
                    }
                } else {
                    outputElement.innerHTML = `<div class="text-danger">Error: ${data.message}</div>`;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                outputElement.innerHTML = `<div class="text-danger">Error executing command: ${error.message}</div>`;
            });
        });
    }
    
    // Setup common device command patterns
    setupCommandTemplates();
});

function setupCommandTemplates() {
    const templateBtn = document.getElementById('commandTemplateBtn');
    const templateModal = document.getElementById('commandTemplateModal');
    
    if (templateBtn && templateModal) {
        // Populate the template list
        const templateList = document.getElementById('commandTemplateList');
        const templates = getCommandTemplates();
        
        templates.forEach((template, index) => {
            const item = document.createElement('button');
            item.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
            item.innerHTML = `
                <div>
                    <strong>${template.name}</strong>
                    <p class="mb-0 small text-muted">${template.description}</p>
                </div>
                <span class="badge bg-primary">${template.device_type || 'All'}</span>
            `;
            
            item.addEventListener('click', function() {
                const customCommand = document.getElementById('customCommand');
                const commandSelect = document.getElementById('commandSelect');
                
                // Set custom command
                commandSelect.value = 'custom';
                customCommand.style.display = 'block';
                customCommand.value = template.command;
                
                // Close modal
                const modal = bootstrap.Modal.getInstance(templateModal);
                modal.hide();
            });
            
            templateList.appendChild(item);
        });
    }
}

function getCommandTemplates() {
    // Common useful command templates for network engineers
    return [
        {
            name: "Show Interface Status",
            command: "show interfaces status",
            description: "Display status of all interfaces",
            device_type: "cisco_ios"
        },
        {
            name: "Check Access Lists",
            command: "show access-lists",
            description: "Display all configured ACLs",
            device_type: "cisco_ios"
        },
        {
            name: "Routing Table",
            command: "show ip route",
            description: "Display IP routing table",
            device_type: "cisco_ios"
        },
        {
            name: "Show VLANs",
            command: "show vlan brief",
            description: "Display VLAN information",
            device_type: "cisco_ios"
        },
        {
            name: "Check CPU Utilization",
            command: "show processes cpu sorted",
            description: "Display CPU utilization",
            device_type: "cisco_ios"
        },
        {
            name: "Check Memory Utilization",
            command: "show memory statistics",
            description: "Display memory usage",
            device_type: "cisco_ios"
        },
        {
            name: "Check AAA Configuration",
            command: "show aaa servers",
            description: "Display AAA server configuration",
            device_type: "cisco_ios"
        },
        {
            name: "Juniper Show Interfaces",
            command: "show interfaces terse",
            description: "Display all interfaces",
            device_type: "juniper_junos"
        },
        {
            name: "Juniper Show Firewall",
            command: "show firewall",
            description: "Display firewall filters",
            device_type: "juniper_junos"
        },
        {
            name: "Juniper Show Security",
            command: "show security policies",
            description: "Display security policies",
            device_type: "juniper_junos"
        },
        {
            name: "Check Running Config",
            command: "show running-config",
            description: "Display the current configuration",
            device_type: "All"
        }
    ];
}