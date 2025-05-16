/**
 * Network Topology Visualization
 * This file handles the interactive network visualization using D3.js
 */

document.addEventListener('DOMContentLoaded', function() {
    // Global variables
    let testModeEnabled = false;
    let networkData = null;
    let simulation = null;
    let svg = null;
    let activeConnectionId = null;
    let connectionModal = null;
    let deleteModal = null;
    
    // Initialize modals
    connectionModal = new bootstrap.Modal(document.getElementById('connectionModal'));
    deleteModal = new bootstrap.Modal(document.getElementById('deleteConnectionModal'));
    
    // Fetch initial topology data
    fetchTopologyData();
    
    // Test mode toggle button
    const testModeBtn = document.getElementById('testModeBtn');
    const testModeText = document.getElementById('testModeText');
    const testModeAlert = document.getElementById('testModeAlert');
    
    testModeBtn.addEventListener('click', toggleTestMode);
    
    // Layout buttons
    document.getElementById('layoutCircleBtn').addEventListener('click', function() {
        updateActiveLayoutButton(this);
        applyCircleLayout();
    });
    
    document.getElementById('layoutGridBtn').addEventListener('click', function() {
        updateActiveLayoutButton(this);
        applyGridLayout();
    });
    
    document.getElementById('layoutForceBtn').addEventListener('click', function() {
        updateActiveLayoutButton(this);
        applyForceLayout();
    });
    
    // Add connection button
    document.getElementById('addConnectionBtn').addEventListener('click', function() {
        resetConnectionForm();
        document.getElementById('connectionModalTitle').textContent = 'Add Connection';
    });
    
    // Edit connection button
    document.getElementById('editConnectionBtn').addEventListener('click', function() {
        document.getElementById('connectionModalTitle').textContent = 'Edit Connection';
        // Form is already populated from selectConnection
    });
    
    // Save connection button
    document.getElementById('saveConnectionBtn').addEventListener('click', saveConnection);
    
    // Delete connection buttons
    document.getElementById('deleteConnectionBtn').addEventListener('click', function() {
        const connection = networkData.links.find(link => link.id === activeConnectionId);
        if (connection) {
            const sourceDevice = networkData.nodes.find(node => node.id === connection.source.id);
            const targetDevice = networkData.nodes.find(node => node.id === connection.target.id);
            
            document.getElementById('deleteConnectionDetails').textContent = 
                `Connection from ${sourceDevice.name} to ${targetDevice.name} 
                (${connection.connection_type})`;
            
            deleteModal.show();
        }
    });
    
    document.getElementById('confirmDeleteConnectionBtn').addEventListener('click', function() {
        deleteConnection(activeConnectionId);
        deleteModal.hide();
    });
    
    /**
     * Toggle test mode on/off
     */
    function toggleTestMode() {
        const newState = !testModeEnabled;
        
        // Update UI while waiting for response
        testModeBtn.disabled = true;
        
        // Send request to server
        fetch('/api/test-mode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                enable: newState
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                testModeEnabled = data.test_mode;
                updateTestModeUI();
                
                // Refresh data
                fetchTopologyData();
            } else {
                alert('Failed to toggle test mode: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error toggling test mode:', error);
            alert('Error toggling test mode');
        })
        .finally(() => {
            testModeBtn.disabled = false;
        });
    }
    
    /**
     * Update test mode UI elements
     */
    function updateTestModeUI() {
        if (testModeEnabled) {
            testModeBtn.classList.remove('btn-danger');
            testModeBtn.classList.add('btn-secondary');
            testModeText.textContent = 'Disable Test Mode';
            testModeAlert.style.display = 'block';
        } else {
            testModeBtn.classList.remove('btn-secondary');
            testModeBtn.classList.add('btn-danger');
            testModeText.textContent = 'Enable Test Mode';
            testModeAlert.style.display = 'none';
        }
    }
    
    /**
     * Check current test mode status
     */
    function checkTestModeStatus() {
        fetch('/api/test-status')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    testModeEnabled = data.test_mode;
                    updateTestModeUI();
                }
            })
            .catch(error => {
                console.error('Error checking test mode status:', error);
            });
    }
    
    /**
     * Fetch network topology data from the server
     */
    function fetchTopologyData() {
        fetch('/api/topology')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    networkData = data.data;
                    renderNetworkTopology(networkData);
                } else {
                    console.error('Error fetching topology data:', data.message);
                }
            })
            .catch(error => {
                console.error('Error fetching topology data:', error);
            });
    }
    
    /**
     * Render network topology visualization using D3.js
     */
    function renderNetworkTopology(data) {
        // Clear previous visualization
        d3.select('#topology').html('');
        
        // Set up SVG canvas
        const width = document.getElementById('topology').clientWidth;
        const height = document.getElementById('topology').clientHeight;
        
        svg = d3.select('#topology')
            .append('svg')
            .attr('width', width)
            .attr('height', height);
            
        // Create force simulation
        simulation = d3.forceSimulation(data.nodes)
            .force('link', d3.forceLink(data.links).id(d => d.id).distance(150))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(50));

        // Create links
        const link = svg.append('g')
            .selectAll('line')
            .data(data.links)
            .enter()
            .append('line')
            .attr('class', d => `link connection-${d.status}`)
            .attr('id', d => `link-${d.id}`)
            .on('click', selectConnection);
            
        // Create nodes
        const node = svg.append('g')
            .selectAll('.node')
            .data(data.nodes)
            .enter()
            .append('g')
            .attr('class', 'node')
            .attr('id', d => `node-${d.id}`)
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Add device icons and text
        node.append('circle')
            .attr('r', 25)
            .attr('fill', getNodeColor);
            
        // Add device type icon
        node.append('text')
            .attr('y', 5)
            .text(d => getDeviceIcon(d.device_type));
            
        // Add device name below icon    
        node.append('text')
            .attr('y', 40)
            .text(d => d.name);
            
        // Update positions on simulation tick
        simulation.on('tick', () => {
            link
                .attr('x1', d => Math.max(30, Math.min(width - 30, d.source.x)))
                .attr('y1', d => Math.max(30, Math.min(height - 30, d.source.y)))
                .attr('x2', d => Math.max(30, Math.min(width - 30, d.target.x)))
                .attr('y2', d => Math.max(30, Math.min(height - 30, d.target.y)));

            node
                .attr('transform', d => {
                    const x = Math.max(30, Math.min(width - 30, d.x));
                    const y = Math.max(30, Math.min(height - 30, d.y));
                    return `translate(${x}, ${y})`;
                });
        });
        
        // Handle window resize
        window.addEventListener('resize', () => {
            const newWidth = document.getElementById('topology').clientWidth;
            const newHeight = document.getElementById('topology').clientHeight;
            
            svg.attr('width', newWidth)
                .attr('height', newHeight);
                
            simulation.force('center', d3.forceCenter(newWidth / 2, newHeight / 2))
                .alpha(0.3)
                .restart();
        });
    }
    
    /**
     * Get node color based on device status
     */
    function getNodeColor(d) {
        if (!d.status || d.status === 'unknown') {
            return '#6c757d';  // Secondary/gray for unknown
        }
        
        switch (d.status) {
            case 'up':
                return '#198754';  // Success/green
            case 'degraded':
                return '#fd7e14';  // Warning/orange
            case 'down':
                return '#dc3545';  // Danger/red
            default:
                return '#6c757d';  // Secondary/gray
        }
    }
    
    /**
     * Get Font Awesome icon for device type
     */
    function getDeviceIcon(deviceType) {
        switch (deviceType) {
            case 'cisco_ios':
            case 'cisco_xe':
            case 'cisco_nxos':
                return '\uf6ff';  // Network wired
            case 'cisco_asa':
                return '\uf3ed';  // Shield
            case 'juniper_junos':
            case 'arista_eos':
                return '\uf233';  // Server
            case 'paloalto_panos':
            case 'fortinet':
                return '\uf49c';  // Shield alt
            case 'linux':
                return '\uf17c';  // Linux
            default:
                return '\uf0e8';  // Sitemap
        }
    }
    
    /**
     * Select connection and show details
     */
    function selectConnection(event, d) {
        // Deselect previously active elements
        d3.selectAll('.link.active').classed('active', false);
        d3.selectAll('.node.active').classed('active', false);
        
        // Select current connection
        activeConnectionId = d.id;
        d3.select(`#link-${d.id}`).classed('active', true);
        d3.select(`#node-${d.source.id}`).classed('active', true);
        d3.select(`#node-${d.target.id}`).classed('active', true);
        
        // Update connection details card
        document.getElementById('connectionInfoCard').style.display = 'block';
        
        // Source device info
        const sourceDevice = networkData.nodes.find(node => node.id === d.source.id);
        document.getElementById('sourceDeviceInfo').innerHTML = `
            <strong>${sourceDevice.name}</strong>
            <div>${sourceDevice.ip_address}</div>
            <div class="badge bg-secondary">${sourceDevice.device_type}</div>
        `;
        
        // Target device info
        const targetDevice = networkData.nodes.find(node => node.id === d.target.id);
        document.getElementById('targetDeviceInfo').innerHTML = `
            <strong>${targetDevice.name}</strong>
            <div>${targetDevice.ip_address}</div>
            <div class="badge bg-secondary">${targetDevice.device_type}</div>
        `;
        
        // Connection details
        document.getElementById('connectionType').textContent = d.connection_type;
        
        const statusClass = d.status === 'active' ? 'success' : 
            (d.status === 'degraded' ? 'warning' : 'danger');
        document.getElementById('connectionStatus').innerHTML = 
            `<span class="badge bg-${statusClass}">${d.status}</span>`;
            
        document.getElementById('connectionBandwidth').textContent = 
            d.bandwidth ? `${d.bandwidth} Mbps` : 'Not specified';
            
        document.getElementById('connectionSourceInterface').textContent = 
            d.interface_source || 'Not specified';
            
        document.getElementById('connectionTargetInterface').textContent = 
            d.interface_target || 'Not specified';
            
        document.getElementById('connectionDescription').textContent = 
            d.description || 'No description provided';
            
        // Populate edit form with current connection data
        populateConnectionForm(d);
    }
    
    /**
     * Reset connection form to default values
     */
    function resetConnectionForm() {
        activeConnectionId = null;
        document.getElementById('connectionForm').reset();
        document.getElementById('connectionId').value = '';
    }
    
    /**
     * Populate connection form with connection data
     */
    function populateConnectionForm(connection) {
        document.getElementById('connectionId').value = connection.id;
        document.getElementById('sourceDevice').value = connection.source.id;
        document.getElementById('targetDevice').value = connection.target.id;
        document.getElementById('connectionType').value = connection.connection_type;
        document.getElementById('connectionStatus').value = connection.status;
        document.getElementById('connectionBandwidth').value = connection.bandwidth || '';
        document.getElementById('sourceInterface').value = connection.interface_source || '';
        document.getElementById('targetInterface').value = connection.interface_target || '';
        document.getElementById('connectionDescription').value = connection.description || '';
    }
    
    /**
     * Save connection (create or update)
     */
    function saveConnection() {
        const form = document.getElementById('connectionForm');
        
        // Basic form validation
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }
        
        // Get form data
        const connectionId = document.getElementById('connectionId').value;
        const formData = {
            source_device_id: parseInt(document.getElementById('sourceDevice').value),
            target_device_id: parseInt(document.getElementById('targetDevice').value),
            connection_type: document.getElementById('connectionType').value,
            status: document.getElementById('connectionStatus').value,
            bandwidth: document.getElementById('connectionBandwidth').value ? 
                parseInt(document.getElementById('connectionBandwidth').value) : null,
            interface_source: document.getElementById('sourceInterface').value,
            interface_target: document.getElementById('targetInterface').value,
            description: document.getElementById('connectionDescription').value
        };
        
        // Validate that source and target are different
        if (formData.source_device_id === formData.target_device_id) {
            alert('Source and target devices must be different');
            return;
        }
        
        // Determine if this is an edit or create operation
        const url = connectionId ? 
            `/api/connections/${connectionId}` : 
            '/api/connections';
            
        const method = connectionId ? 'PUT' : 'POST';
        
        // Send request to server
        fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Refresh topology data
                fetchTopologyData();
                connectionModal.hide();
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error saving connection:', error);
            alert('Error saving connection');
        });
    }
    
    /**
     * Delete connection
     */
    function deleteConnection(connectionId) {
        fetch(`/api/connections/${connectionId}`, {
            method: 'DELETE'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Hide connection info card
                document.getElementById('connectionInfoCard').style.display = 'none';
                
                // Refresh topology data
                fetchTopologyData();
                activeConnectionId = null;
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error deleting connection:', error);
            alert('Error deleting connection');
        });
    }
    
    /**
     * Update active layout button
     */
    function updateActiveLayoutButton(button) {
        document.querySelectorAll('.btn-group .btn').forEach(btn => {
            btn.classList.remove('active');
        });
        button.classList.add('active');
    }
    
    /**
     * Apply circle layout
     */
    function applyCircleLayout() {
        if (!simulation || !networkData) return;
        
        // Stop current simulation
        simulation.stop();
        
        const width = document.getElementById('topology').clientWidth;
        const height = document.getElementById('topology').clientHeight;
        const radius = Math.min(width, height) / 2 - 100;
        const nodeCount = networkData.nodes.length;
        
        // Position nodes in a circle
        networkData.nodes.forEach((node, i) => {
            const angle = (i / nodeCount) * 2 * Math.PI;
            node.x = width / 2 + radius * Math.cos(angle);
            node.y = height / 2 + radius * Math.sin(angle);
            node.fx = node.x;
            node.fy = node.y;
        });
        
        // Update visualization
        simulation.alpha(0.1).restart();
        
        // Release fixed positions after a short delay
        setTimeout(() => {
            networkData.nodes.forEach(node => {
                node.fx = null;
                node.fy = null;
            });
        }, 1500);
    }
    
    /**
     * Apply grid layout
     */
    function applyGridLayout() {
        if (!simulation || !networkData) return;
        
        // Stop current simulation
        simulation.stop();
        
        const width = document.getElementById('topology').clientWidth;
        const height = document.getElementById('topology').clientHeight;
        const nodeCount = networkData.nodes.length;
        
        // Calculate grid dimensions
        const cols = Math.ceil(Math.sqrt(nodeCount));
        const cellWidth = width / (cols + 1);
        const cellHeight = height / (Math.ceil(nodeCount / cols) + 1);
        
        // Position nodes in a grid
        networkData.nodes.forEach((node, i) => {
            const col = i % cols;
            const row = Math.floor(i / cols);
            node.x = cellWidth * (col + 1);
            node.y = cellHeight * (row + 1);
            node.fx = node.x;
            node.fy = node.y;
        });
        
        // Update visualization
        simulation.alpha(0.1).restart();
        
        // Release fixed positions after a short delay
        setTimeout(() => {
            networkData.nodes.forEach(node => {
                node.fx = null;
                node.fy = null;
            });
        }, 1500);
    }
    
    /**
     * Apply force-directed layout
     */
    function applyForceLayout() {
        if (!simulation || !networkData) return;
        
        // Clear any fixed positions
        networkData.nodes.forEach(node => {
            node.fx = null;
            node.fy = null;
        });
        
        // Restart simulation with high alpha to reorganize
        simulation.alpha(0.5).restart();
    }
    
    /**
     * D3 drag start handler
     */
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    /**
     * D3 drag handler
     */
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    /**
     * D3 drag end handler
     */
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    // Check test mode status on page load
    checkTestModeStatus();
});