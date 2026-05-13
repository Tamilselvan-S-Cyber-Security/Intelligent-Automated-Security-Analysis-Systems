/**
 * CyberWolf - Custom JavaScript for enhanced UI functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    
    // Enable all tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Enable all popovers
    const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]');
    const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl));
    
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Copy to clipboard functionality for code blocks
    document.querySelectorAll('pre code').forEach(codeBlock => {
        // Create copy button
        const copyButton = document.createElement('button');
        copyButton.className = 'btn btn-sm btn-outline-light copy-button';
        copyButton.type = 'button';
        copyButton.innerText = 'Copy';
        copyButton.style.position = 'absolute';
        copyButton.style.right = '1rem';
        copyButton.style.top = '0.5rem';
        
        // Add copy functionality
        copyButton.addEventListener('click', function() {
            const textToCopy = codeBlock.innerText;
            navigator.clipboard.writeText(textToCopy).then(() => {
                copyButton.innerText = 'Copied!';
                setTimeout(() => {
                    copyButton.innerText = 'Copy';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy text: ', err);
            });
        });
        
        // Position the code block container relatively
        const preElement = codeBlock.parentElement;
        preElement.style.position = 'relative';
        
        // Add the button to the code block
        preElement.appendChild(copyButton);
    });
    
    // Handle scan form submission
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function() {
            const scanButton = document.getElementById('scanButton');
            const scanSpinner = document.getElementById('scanSpinner');
            const scanButtonText = document.getElementById('scanButtonText');
            
            scanButtonText.textContent = 'Scanning...';
            scanSpinner.classList.remove('d-none');
            scanButton.disabled = true;
        });
    }
    
    // Toggle API key input based on scan type
    const apiScanRadio = document.getElementById('apiScan');
    const basicScanRadio = document.getElementById('basicScan');
    if (apiScanRadio && basicScanRadio) {
        const apiKeySection = document.querySelector('.api-key-section');
        
        apiScanRadio.addEventListener('change', function() {
            if (this.checked) {
                apiKeySection.classList.remove('d-none');
            }
        });
        
        basicScanRadio.addEventListener('change', function() {
            if (this.checked) {
                apiKeySection.classList.add('d-none');
            }
        });
    }
    
    // Format JSON data if present
    document.querySelectorAll('.json-data').forEach(element => {
        try {
            const jsonData = JSON.parse(element.textContent);
            element.textContent = JSON.stringify(jsonData, null, 2);
        } catch (e) {
            // Not valid JSON, leave as is
            console.warn('Failed to parse JSON data', e);
        }
    });
    
    // Add active class to current nav item based on URL
    const currentLocation = window.location.pathname;
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        if (link.getAttribute('href') === currentLocation) {
            link.classList.add('active');
        }
    });
    
    // Handle collapsible sections in the documentation
    document.querySelectorAll('.collapse-trigger').forEach(trigger => {
        trigger.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement.classList.contains('show')) {
                targetElement.classList.remove('show');
                this.querySelector('.collapse-icon').textContent = '+';
            } else {
                targetElement.classList.add('show');
                this.querySelector('.collapse-icon').textContent = '-';
            }
        });
    });
});