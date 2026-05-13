// Handle scan form submission
document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            const attackOptions = document.querySelectorAll('input[type="checkbox"][name^="attack_"]');
            let hasSelected = false;
            attackOptions.forEach(option => {
                if (option.checked) hasSelected = true;
            });
            
            if (!hasSelected) {
                e.preventDefault();
                alert('Please select at least one attack type to perform.');
            }
        });
    }

    // Copy API key to clipboard
    const copyButtons = document.querySelectorAll('.copy-api-key');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const apiKey = this.getAttribute('data-key');
            navigator.clipboard.writeText(apiKey).then(() => {
                this.textContent = 'Copied!';
                setTimeout(() => {
                    this.textContent = 'Copy';
                }, 2000);
            });
        });
    });
});