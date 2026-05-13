// Cybersecurity Tips Carousel
document.addEventListener('DOMContentLoaded', function() {
    // Initialize carousel
    initCarousel();
});

function initCarousel() {
    const slides = document.querySelectorAll('.tip-slide');
    const indicators = document.querySelectorAll('.tip-indicator');
    const prevButton = document.querySelector('.prev-tip');
    const nextButton = document.querySelector('.next-tip');
    const autoAdvanceInterval = 8000; // Auto advance every 8 seconds
    
    let currentIndex = 0;
    let autoAdvanceTimer = null;
    
    // Initialize the first slide
    if (slides.length > 0) {
        slides[currentIndex].classList.add('active');
        if (indicators.length > 0) {
            indicators[currentIndex].classList.add('active');
        }
    }
    
    // Start auto-advancing
    startAutoAdvance();
    
    // Stop auto-advance when user interacts with controls
    if (prevButton) {
        prevButton.addEventListener('click', function() {
            resetAutoAdvance();
            showPreviousSlide();
        });
    }
    
    if (nextButton) {
        nextButton.addEventListener('click', function() {
            resetAutoAdvance();
            showNextSlide();
        });
    }
    
    // Add indicator click events
    indicators.forEach((indicator, index) => {
        indicator.addEventListener('click', function() {
            resetAutoAdvance();
            goToSlide(index);
        });
    });
    
    function showNextSlide() {
        slides[currentIndex].classList.remove('active');
        indicators[currentIndex].classList.remove('active');
        
        currentIndex = (currentIndex + 1) % slides.length;
        
        slides[currentIndex].classList.add('active');
        indicators[currentIndex].classList.add('active');
    }
    
    function showPreviousSlide() {
        slides[currentIndex].classList.remove('active');
        indicators[currentIndex].classList.remove('active');
        
        currentIndex = (currentIndex - 1 + slides.length) % slides.length;
        
        slides[currentIndex].classList.add('active');
        indicators[currentIndex].classList.add('active');
    }
    
    function goToSlide(index) {
        if (index >= 0 && index < slides.length && index !== currentIndex) {
            slides[currentIndex].classList.remove('active');
            indicators[currentIndex].classList.remove('active');
            
            currentIndex = index;
            
            slides[currentIndex].classList.add('active');
            indicators[currentIndex].classList.add('active');
        }
    }
    
    function startAutoAdvance() {
        if (autoAdvanceTimer === null) {
            autoAdvanceTimer = setInterval(showNextSlide, autoAdvanceInterval);
        }
    }
    
    function resetAutoAdvance() {
        if (autoAdvanceTimer !== null) {
            clearInterval(autoAdvanceTimer);
            autoAdvanceTimer = null;
            startAutoAdvance();
        }
    }
    
    // Pause auto-advance when user hovers over the carousel
    const carousel = document.querySelector('.cyber-tip-carousel');
    if (carousel) {
        carousel.addEventListener('mouseenter', function() {
            if (autoAdvanceTimer !== null) {
                clearInterval(autoAdvanceTimer);
                autoAdvanceTimer = null;
            }
        });
        
        carousel.addEventListener('mouseleave', function() {
            startAutoAdvance();
        });
    }
}

// Function to manually advance the carousel from Streamlit callbacks
function advanceCarousel(direction) {
    const event = new CustomEvent('carouselAdvance', { 
        detail: { direction: direction } 
    });
    document.dispatchEvent(event);
}

// Listen for custom events from Streamlit
document.addEventListener('carouselAdvance', function(e) {
    const slides = document.querySelectorAll('.tip-slide');
    const indicators = document.querySelectorAll('.tip-indicator');
    let currentIndex = Array.from(slides).findIndex(slide => slide.classList.contains('active'));
    
    if (currentIndex === -1) return;
    
    slides[currentIndex].classList.remove('active');
    indicators[currentIndex].classList.remove('active');
    
    if (e.detail.direction === 'next') {
        currentIndex = (currentIndex + 1) % slides.length;
    } else {
        currentIndex = (currentIndex - 1 + slides.length) % slides.length;
    }
    
    slides[currentIndex].classList.add('active');
    indicators[currentIndex].classList.add('active');
});