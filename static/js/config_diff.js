// Configuration difference analyzer

document.addEventListener('DOMContentLoaded', function() {
    setupConfigDiff();
});

function setupConfigDiff() {
    const compareBtn = document.getElementById('compareConfigsBtn');
    if (!compareBtn) return;
    
    compareBtn.addEventListener('click', function() {
        const backup1Id = document.getElementById('backup1Select').value;
        const backup2Id = document.getElementById('backup2Select').value;
        
        if (backup1Id === backup2Id) {
            showAlert('Please select different backups to compare', 'warning');
            return;
        }
        
        // Show loading state
        const diffOutput = document.getElementById('configDiffOutput');
        diffOutput.innerHTML = '<div class="text-center my-3"><div class="spinner-border text-light" role="status"></div><p class="mt-2">Analyzing differences...</p></div>';
        
        // Fetch configurations
        Promise.all([
            fetch(`/api/backups/${backup1Id}`).then(resp => resp.json()),
            fetch(`/api/backups/${backup2Id}`).then(resp => resp.json())
        ])
        .then(([backup1, backup2]) => {
            if (backup1.status === 'success' && backup2.status === 'success') {
                // Perform diff
                const diff = calculateDiff(backup1.config, backup2.config);
                
                // Display results
                renderDiff(diff, diffOutput, backup1.timestamp, backup2.timestamp);
            } else {
                diffOutput.innerHTML = '<div class="alert alert-danger">Error fetching configurations</div>';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            diffOutput.innerHTML = `<div class="alert alert-danger">Error comparing configurations: ${error.message}</div>`;
        });
    });
}

function calculateDiff(oldConfig, newConfig) {
    // Split configs into lines and remove empty lines
    const oldLines = oldConfig.split('\n').filter(line => line.trim() !== '');
    const newLines = newConfig.split('\n').filter(line => line.trim() !== '');
    
    // Find added and removed lines
    const added = newLines.filter(line => !oldLines.includes(line));
    const removed = oldLines.filter(line => !newLines.includes(line));
    
    return {
        added: added,
        removed: removed,
        addedCount: added.length,
        removedCount: removed.length
    };
}

function renderDiff(diff, container, timestamp1, timestamp2) {
    let html = '';
    
    html += `<div class="alert alert-info">
        <h5><i class="fas fa-info-circle"></i> Configuration Difference Summary</h5>
        <p>Found ${diff.addedCount} additions and ${diff.removedCount} removals between backups from ${formatDate(timestamp1)} and ${formatDate(timestamp2)}.</p>
    </div>`;
    
    if (diff.addedCount === 0 && diff.removedCount === 0) {
        html += '<div class="alert alert-success">No differences found between the selected configurations.</div>';
    } else {
        // Added lines
        if (diff.addedCount > 0) {
            html += '<h5 class="mt-4 text-success">Added Configuration Lines:</h5>';
            html += '<div class="bg-dark p-3 mb-4 rounded">';
            diff.added.forEach(line => {
                html += `<div class="text-success"><i class="fas fa-plus"></i> ${escapeHtml(line)}</div>`;
            });
            html += '</div>';
        }
        
        // Removed lines
        if (diff.removedCount > 0) {
            html += '<h5 class="mt-4 text-danger">Removed Configuration Lines:</h5>';
            html += '<div class="bg-dark p-3 mb-4 rounded">';
            diff.removed.forEach(line => {
                html += `<div class="text-danger"><i class="fas fa-minus"></i> ${escapeHtml(line)}</div>`;
            });
            html += '</div>';
        }
        
        // Export buttons
        html += `<div class="mt-4">
            <button class="btn btn-sm btn-outline-light" onclick="exportDiff('${escapeHtml(JSON.stringify(diff))}', 'text')">
                <i class="fas fa-file-export"></i> Export as Text
            </button>
            <button class="btn btn-sm btn-outline-light ms-2" onclick="exportDiff('${escapeHtml(JSON.stringify(diff))}', 'csv')">
                <i class="fas fa-file-csv"></i> Export as CSV
            </button>
        </div>`;
    }
    
    container.innerHTML = html;
}

function exportDiff(diffJson, format) {
    const diff = JSON.parse(diffJson);
    let content = '';
    
    if (format === 'text') {
        content = `Configuration Difference Report\n`;
        content += `Generated: ${new Date().toISOString()}\n`;
        content += `===============================\n\n`;
        content += `Summary: ${diff.addedCount} additions, ${diff.removedCount} removals\n\n`;
        
        if (diff.addedCount > 0) {
            content += `ADDED CONFIGURATION LINES:\n`;
            content += `------------------------------\n`;
            diff.added.forEach(line => {
                content += `+ ${line}\n`;
            });
            content += `\n`;
        }
        
        if (diff.removedCount > 0) {
            content += `REMOVED CONFIGURATION LINES:\n`;
            content += `------------------------------\n`;
            diff.removed.forEach(line => {
                content += `- ${line}\n`;
            });
        }
        
        // Create file and download
        downloadFile(content, 'config_diff.txt', 'text/plain');
    } 
    else if (format === 'csv') {
        content = `Type,Line\n`;
        
        diff.added.forEach(line => {
            content += `Added,"${line.replace(/"/g, '""')}"\n`;
        });
        
        diff.removed.forEach(line => {
            content += `Removed,"${line.replace(/"/g, '""')}"\n`;
        });
        
        // Create file and download
        downloadFile(content, 'config_diff.csv', 'text/csv');
    }
}

function downloadFile(content, filename, contentType) {
    const a = document.createElement('a');
    const file = new Blob([content], {type: contentType});
    a.href = URL.createObjectURL(file);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function formatDate(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}