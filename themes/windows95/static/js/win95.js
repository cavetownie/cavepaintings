// Windows 95 Theme JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initButtonEffects();
    initDialogs();
});

function initButtonEffects() {
    const buttons = document.querySelectorAll('button, .start-button, .window-control');
    
    buttons.forEach(button => {
        button.addEventListener('mousedown', function() {
            this.style.borderStyle = 'inset';
        });
        
        button.addEventListener('mouseup', function() {
            this.style.borderStyle = 'outset';
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.borderStyle = 'outset';
        });
    });
}

function initDialogs() {
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('dialog-overlay')) {
            closeDialog(e.target.closest('.dialog'));
        }
    });
}
