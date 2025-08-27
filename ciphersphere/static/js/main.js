// CipherSphere Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Icon fallback handler
    function checkIconsLoaded() {
        const icons = document.querySelectorAll('i[class*="fa-"]');
        icons.forEach(function(icon) {
            // Check if the icon actually has content
            const computedStyle = window.getComputedStyle(icon, '::before');
            const content = computedStyle.getPropertyValue('content');
            
            // Also check if the icon is effectively invisible
            const iconRect = icon.getBoundingClientRect();
            const hasNoVisibleContent = content === 'none' || content === '""' || content === '' || 
                                      iconRect.width === 0 || iconRect.height === 0;
            
            if (hasNoVisibleContent) {
                // Icon didn't load, add fallback
                addIconFallback(icon);
            }
        });
        
        // Also check for broken brand icons specifically
        const brandIcons = document.querySelectorAll('.cyber-brand i, .navbar-brand i');
        brandIcons.forEach(function(icon) {
            if (!icon.innerHTML && icon.classList.contains('fa-shield-alt')) {
                icon.innerHTML = '🛡️';
                icon.style.fontFamily = 'inherit';
            }
        });
    }
    
    function addIconFallback(iconElement) {
        const iconMap = {
            'fa-file-lock': '🔒',
            'fa-share-alt': '🔗', 
            'fa-activity': '📊',
            'fa-shield-alt': '🛡️',
            'fa-tachometer-alt': '📊',
            'fa-history': '📅',
            'fa-lock': '🔒',
            'fa-unlock': '🔓',
            'fa-users': '👥',
            'fa-chart-line': '📈',
            'fa-cog': '⚙️',
            'fa-arrow-left': '←',
            'fa-user-shield': '👤',
            'fa-server': '🖥️',
            'fa-sign-in-alt': '⏵',
            'fa-sign-out-alt': '⏸',
            'fa-file': '📄',
            'fa-edit': '✏️',
            'fa-file-upload': '📤',
            'fa-cloud-upload-alt': '☁️',
            'fa-random': '🔀',
            'fa-sync': '🔄',
            'fa-copy': '📋',
            'fa-download': '⬇️',
            'fa-arrow-up': '↑',
            'fa-check': '✓',
            'fa-vault': '🏦',
            'fa-key': '🔑',
            'fa-trash': '🗑️',
            'fa-file-alt': '📝',
            'fa-file-image': '🖼️',
            'fa-file-pdf': '📋',
            'fa-file-word': '📄',
            'fa-file-archive': '📦',
            'fa-search': '🔍',
            'fa-filter': '🔽',
            'fa-sort': '🔄',
            'fa-eye': '👁️',
            'fa-eye-slash': '🚫',
            'fa-times': '✖️',
            'fa-plus': '➕',
            'fa-minus': '➖',
            'fa-info-circle': 'ℹ️',
            'fa-exclamation-triangle': '⚠️'
        };
        
        // Find which icon class this element has
        for (const className of iconElement.classList) {
            if (iconMap[className]) {
                iconElement.innerHTML = iconMap[className];
                iconElement.style.fontFamily = 'inherit';
                iconElement.style.fontSize = 'inherit';
                iconElement.style.fontWeight = 'normal';
                break;
            }
        }
        
        // If no mapping found, try to extract icon name and use a generic symbol
        if (!iconElement.innerHTML) {
            const faClass = Array.from(iconElement.classList).find(cls => cls.startsWith('fa-'));
            if (faClass) {
                // Generic fallback based on icon category
                if (faClass.includes('user') || faClass.includes('person')) {
                    iconElement.innerHTML = '👤';
                } else if (faClass.includes('file') || faClass.includes('document')) {
                    iconElement.innerHTML = '📄';
                } else if (faClass.includes('shield') || faClass.includes('security')) {
                    iconElement.innerHTML = '🛡️';
                } else if (faClass.includes('lock') || faClass.includes('key')) {
                    iconElement.innerHTML = '🔒';
                } else if (faClass.includes('chart') || faClass.includes('graph')) {
                    iconElement.innerHTML = '📊';
                } else {
                    iconElement.innerHTML = '●'; // Generic bullet point
                }
                iconElement.style.fontFamily = 'inherit';
                iconElement.style.fontSize = 'inherit';
            }
        }
    }
    
    // Check icons after a short delay to allow Font Awesome to load
    setTimeout(checkIconsLoaded, 1000);
    
    // Also recheck after page fully loads
    window.addEventListener('load', function() {
        setTimeout(checkIconsLoaded, 500);
    });
    
    // Check for AUTO button functionality on encrypt page
    if (window.location.pathname.includes('/encrypt')) {
        // Ensure AUTO button works even if API fails
        const autoBtn = document.querySelector('.btn-info');
        if (autoBtn) {
            autoBtn.addEventListener('click', function(e) {
                e.preventDefault();
                if (typeof toggleAutoGenerate === 'function') {
                    toggleAutoGenerate();
                } else {
                    console.log('toggleAutoGenerate function not found, using fallback');
                    // Simple fallback for auto generation
                    const keyField = document.getElementById('encryptionKey');
                    if (keyField) {
                        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
                        let key = '';
                        for (let i = 0; i < 32; i++) {
                            key += chars.charAt(Math.floor(Math.random() * chars.length));
                        }
                        keyField.value = key;
                    }
                }
            });
        }
    }
    
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Flash message auto-hide
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(function(message) {
        setTimeout(function() {
            message.style.opacity = '0';
            setTimeout(function() {
                message.remove();
            }, 300);
        }, 5000);
    });

    // Form validation enhancements
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(function(field) {
                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add('is-invalid');
                } else {
                    field.classList.remove('is-invalid');
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Please fill in all required fields.');
            }
        });
    });

    // Password strength indicator
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(function(field) {
        if (field.name.includes('new_password') || field.name.includes('password')) {
            field.addEventListener('input', function() {
                const strength = checkPasswordStrength(this.value);
                updatePasswordStrengthIndicator(this, strength);
            });
        }
    });

    // File size validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(function(input) {
        input.addEventListener('change', function() {
            const maxSize = 50 * 1024 * 1024; // 50MB
            if (this.files[0] && this.files[0].size > maxSize) {
                alert('File size exceeds 50MB limit. Please choose a smaller file.');
                this.value = '';
            }
        });
    });
});

function checkPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]/)) strength++;
    if (password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    if (password.match(/[^a-zA-Z0-9]/)) strength++;
    
    return strength;
}

function updatePasswordStrengthIndicator(field, strength) {
    let indicator = field.parentNode.querySelector('.password-strength');
    
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.className = 'password-strength';
        field.parentNode.appendChild(indicator);
    }
    
    const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    const colors = ['#ff3366', '#ff6600', '#ffaa00', '#66cc00', '#00cc66'];
    
    indicator.textContent = levels[strength - 1] || 'Very Weak';
    indicator.style.color = colors[strength - 1] || colors[0];
}

// Utility functions
function showLoading(element) {
    element.disabled = true;
    element.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
}

function hideLoading(element, originalText) {
    element.disabled = false;
    element.innerHTML = originalText;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showNotification('Copied to clipboard!', 'success');
    }).catch(function() {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showNotification('Copied to clipboard!', 'success');
    });
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'info'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// Export functions for global use
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.copyToClipboard = copyToClipboard;
window.showNotification = showNotification;

// Admin Panel Toggle
let adminPanelOpen = false;

function toggleAdminPanel() {
    const panel = document.getElementById('quickAdminPanel');
    const overlay = document.getElementById('adminPanelOverlay');
    const toggleBtn = document.getElementById('adminToggle');
    
    if (!panel || !overlay) return;
    
    adminPanelOpen = !adminPanelOpen;
    
    if (adminPanelOpen) {
        panel.classList.add('active');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
        
        if (toggleBtn) {
            toggleBtn.innerHTML = '<i class="fas fa-times"></i> Close Admin';
        }
        
        // Load admin stats
        loadAdminStats();
    } else {
        panel.classList.remove('active');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
        
        if (toggleBtn) {
            toggleBtn.innerHTML = '<i class="fas fa-tools"></i> Quick Admin';
        }
    }
}

function loadAdminStats() {
    // Load admin statistics via AJAX
    fetch('/admin/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalUsers').textContent = data.total_users || '0';
            document.getElementById('totalFiles').textContent = data.total_files || '0';
            document.getElementById('activitiesToday').textContent = data.activities_today || '0';
        })
        .catch(error => {
            console.error('Error loading admin stats:', error);
            document.getElementById('totalUsers').textContent = 'Error';
            document.getElementById('totalFiles').textContent = 'Error';
            document.getElementById('activitiesToday').textContent = 'Error';
        });
}

// Close admin panel on escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape' && adminPanelOpen) {
        toggleAdminPanel();
    }
});

// Export admin functions
window.toggleAdminPanel = toggleAdminPanel;
window.loadAdminStats = loadAdminStats;
