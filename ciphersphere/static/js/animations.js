/* CipherSphere - Google Earth-Inspired Interactive Animations */

class CipherSphereAnimations {
    constructor() {
        this.mouseX = 0;
        this.mouseY = 0;
        this.init();
    }

    init() {
        this.setupMouseTracking();
        this.setupAdminSidebar();
        this.setupScrollAnimations();
        this.setupFloatingShapes();
        this.setupPageLoadAnimations();
        this.setupInteractiveElements();
        this.setupParallaxEffects();
        this.setupQuantumLoader();
        this.setupRippleEffects();
        this.setupMagneticElements();
        this.createLoadingScreen();
    }

    createLoadingScreen() {
        const loadingScreen = document.createElement('div');
        loadingScreen.id = 'loading-screen';
        loadingScreen.innerHTML = `
            <div class="loading-content">
                <div class="loading-sphere">
                    <div class="loading-ring"></div>
                    <div class="loading-ring"></div>
                    <div class="loading-ring"></div>
                </div>
                <h2 class="loading-text">CIPHERSPHERE</h2>
                <div class="loading-bar">
                    <div class="loading-progress"></div>
                </div>
                <p class="loading-subtext">Initializing Quantum Encryption</p>
            </div>
        `;
        
        document.body.appendChild(loadingScreen);
        
        // Auto-remove loading screen
        setTimeout(() => {
            if (loadingScreen.parentNode) {
                loadingScreen.parentNode.removeChild(loadingScreen);
            }
        }, 4000);
    }

    // Google Earth-like Mouse Tracking
    setupMouseTracking() {
        document.addEventListener('mousemove', (e) => {
            this.mouseX = (e.clientX / window.innerWidth) * 100;
            this.mouseY = (e.clientY / window.innerHeight) * 100;
            
            document.documentElement.style.setProperty('--mouse-x', `${this.mouseX}%`);
            document.documentElement.style.setProperty('--mouse-y', `${this.mouseY}%`);
            
            // Update 3D logo rotation based on mouse position
            this.updateLogoRotation(e);
            
            // Update parallax elements
            this.updateParallax(e);
            
            // Handle admin sidebar hover tracking
            this.handleAdminSidebarHover(e);
        });
    }

    // Admin Sidebar Hover Tracking
    setupAdminSidebar() {
        // Create hover trigger zone if it doesn't exist
        if (!document.querySelector('.admin-sidebar-trigger')) {
            const trigger = document.createElement('div');
            trigger.className = 'admin-sidebar-trigger';
            document.body.appendChild(trigger);
        }
    }

    handleAdminSidebarHover(e) {
        const sidebar = document.querySelector('.admin-sidebar');
        if (!sidebar) return;

        const triggerZone = 50; // pixels from left edge
        const sidebarWidth = 280; // sidebar width
        const bufferZone = 20; // extra space to prevent flickering

        // Show sidebar when mouse is near left edge or over sidebar
        if (e.clientX <= triggerZone || 
            (e.clientX <= sidebarWidth + bufferZone && sidebar.classList.contains('show'))) {
            sidebar.classList.add('show');
        } 
        // Hide sidebar when mouse moves away
        else if (e.clientX > sidebarWidth + bufferZone) {
            sidebar.classList.remove('show');
        }
    }

    // 3D Logo Interactive Rotation
    updateLogoRotation(e) {
        const logo = document.querySelector('.navbar-brand::before, .cyber-brand::before');
        const rect = document.querySelector('.navbar-brand, .cyber-brand');
        
        if (rect) {
            const centerX = rect.offsetLeft + rect.offsetWidth / 2;
            const centerY = rect.offsetTop + rect.offsetHeight / 2;
            
            const rotateX = (e.clientY - centerY) / 10;
            const rotateY = (e.clientX - centerX) / 10;
            
            rect.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        }
    }

    // Scroll-Based Animations
    setupScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                    this.triggerElementAnimation(entry.target);
                }
            });
        }, observerOptions);

        // Observe all glass cards and important elements
        document.querySelectorAll('.glass-card, .cyber-auth-card, .cyber-dashboard-card, .cyber-stat-card, .cyber-feature-card').forEach(el => {
            observer.observe(el);
        });

        // Add scroll-based parallax
        window.addEventListener('scroll', () => {
            this.handleScrollParallax();
        });
    }

    // Floating Geometric Shapes with Particle System
    setupFloatingShapes() {
        const shapesContainer = document.createElement('div');
        shapesContainer.className = 'floating-shapes';
        document.body.appendChild(shapesContainer);

        // Create particle system
        this.createParticleSystem(shapesContainer);

        // Create multiple floating shapes
        for (let i = 0; i < 8; i++) {
            const shape = document.createElement('div');
            shape.className = 'floating-shape';
            
            const shapeType = Math.random();
            const size = 30 + Math.random() * 60;
            
            shape.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                background: ${this.getRandomGradient()};
                border-radius: ${shapeType > 0.5 ? '50%' : shapeType > 0.3 ? '20%' : '0%'};
                top: ${Math.random() * 100}%;
                left: ${Math.random() * 100}%;
                animation: floatGeometry ${10 + Math.random() * 15}s ease-in-out infinite;
                animation-delay: ${Math.random() * 5}s;
                pointer-events: none;
                z-index: -1;
                filter: blur(${Math.random() * 3}px);
                opacity: ${0.3 + Math.random() * 0.4};
            `;
            shapesContainer.appendChild(shape);
        }
    }

    createParticleSystem(container) {
        for (let i = 0; i < 50; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            
            const size = 1 + Math.random() * 4;
            particle.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                background: ${this.getRandomColor()};
                border-radius: 50%;
                top: ${Math.random() * 100}%;
                left: ${Math.random() * 100}%;
                animation: particleFloat ${20 + Math.random() * 20}s linear infinite;
                animation-delay: ${Math.random() * 10}s;
                pointer-events: none;
                z-index: -1;
                opacity: ${0.4 + Math.random() * 0.6};
                box-shadow: 0 0 ${size * 2}px currentColor;
            `;
            container.appendChild(particle);
        }
    }

    getRandomGradient() {
        const colors = [
            'linear-gradient(45deg, rgba(0, 212, 255, 0.1), rgba(227, 24, 55, 0.05))',
            'linear-gradient(135deg, rgba(0, 255, 136, 0.08), rgba(255, 170, 0, 0.04))',
            'linear-gradient(225deg, rgba(227, 24, 55, 0.06), rgba(0, 212, 255, 0.03))',
            'radial-gradient(circle, rgba(0, 212, 255, 0.1), transparent)',
            'conic-gradient(from 0deg, rgba(0, 255, 136, 0.08), rgba(255, 170, 0, 0.04), rgba(227, 24, 55, 0.06))'
        ];
        return colors[Math.floor(Math.random() * colors.length)];
    }

    getRandomColor() {
        const colors = [
            'rgba(0, 212, 255, 0.8)',
            'rgba(227, 24, 55, 0.6)',
            'rgba(0, 255, 136, 0.7)',
            'rgba(255, 170, 0, 0.5)',
            'rgba(255, 255, 255, 0.4)'
        ];
        return colors[Math.floor(Math.random() * colors.length)];
    }

    // Page Load Animations
    setupPageLoadAnimations() {
        window.addEventListener('load', () => {
            // Animate main title with 3D effect
            const title = document.querySelector('.hero-title, .cyber-title');
            if (title) {
                title.style.animation = 'titleReveal3D 2s ease-out';
                title.setAttribute('data-text', title.textContent);
            }

            // Stagger card animations
            const cards = document.querySelectorAll('.glass-card, .cyber-dashboard-card, .cyber-stat-card');
            cards.forEach((card, index) => {
                setTimeout(() => {
                    card.style.animation = `cardLoad 1s ease-out forwards`;
                    card.style.animationDelay = `${index * 0.1}s`;
                }, 500);
            });

            // Add scan lines to hero section
            const heroSection = document.querySelector('.hero-section, .cyber-hero');
            if (heroSection) {
                heroSection.classList.add('scan-lines');
            }
        });
    }

    // Interactive Elements Enhancement
    setupInteractiveElements() {
        // Add ripple effect to buttons
        document.querySelectorAll('.btn, .cyber-btn-primary, .cyber-btn-secondary').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.createRipple(e, btn);
            });
            
            btn.classList.add('magnetic-hover');
        });

        // Add glitch effect to titles on hover
        document.querySelectorAll('.dashboard-title, .hero-title, .cyber-title').forEach(title => {
            title.addEventListener('mouseenter', () => {
                title.classList.add('glitch-effect', 'holographic-text');
            });
            
            title.addEventListener('mouseleave', () => {
                setTimeout(() => {
                    title.classList.remove('glitch-effect');
                }, 500);
            });
        });

        // Enhanced card interactions
        document.querySelectorAll('.glass-card, .cyber-dashboard-card').forEach(card => {
            card.addEventListener('mouseenter', (e) => {
                this.enhanceCardHover(card, e);
            });
            
            card.addEventListener('mousemove', (e) => {
                this.updateCardTilt(card, e);
            });
            
            card.addEventListener('mouseleave', () => {
                this.resetCardTilt(card);
            });
        });
    }

    // Parallax Effects
    setupParallaxEffects() {
        const parallaxElements = document.querySelectorAll('.glass-card, .cyber-stat-card');
        parallaxElements.forEach(el => {
            el.classList.add('parallax-element');
        });
    }

    handleScrollParallax() {
        const scrolled = window.pageYOffset;
        const parallaxElements = document.querySelectorAll('.parallax-element');
        
        parallaxElements.forEach((el, index) => {
            const speed = 0.5 + (index * 0.1);
            const yPos = -(scrolled * speed);
            el.style.transform = `translateY(${yPos}px)`;
        });
    }

    updateParallax(e) {
        const cards = document.querySelectorAll('.glass-card');
        cards.forEach((card, index) => {
            const rect = card.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;
            
            const rotateX = (e.clientY - centerY) / 50;
            const rotateY = (e.clientX - centerX) / 50;
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });
    }

    // Quantum Loader Setup
    setupQuantumLoader() {
        const loaders = document.querySelectorAll('.loading-spinner');
        loaders.forEach(loader => {
            loader.className = 'quantum-loader';
        });
    }

    // Ripple Effects
    setupRippleEffects() {
        document.querySelectorAll('.glass-card, .cyber-dashboard-card').forEach(el => {
            el.classList.add('ripple-effect');
        });
    }

    createRipple(e, element) {
        const ripple = document.createElement('div');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: radial-gradient(circle, rgba(0, 212, 255, 0.3) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
            animation: ripple 0.8s ease-out;
            z-index: 10;
        `;
        
        element.style.position = 'relative';
        element.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 800);
    }

    // Magnetic Elements
    setupMagneticElements() {
        document.querySelectorAll('.navbar-brand, .cyber-brand, .btn, .cyber-btn-primary').forEach(el => {
            el.classList.add('magnetic-hover');
            
            el.addEventListener('mousemove', (e) => {
                const rect = el.getBoundingClientRect();
                const x = e.clientX - rect.left - rect.width / 2;
                const y = e.clientY - rect.top - rect.height / 2;
                
                el.style.transform = `translate(${x * 0.1}px, ${y * 0.1}px) scale(1.05)`;
            });
            
            el.addEventListener('mouseleave', () => {
                el.style.transform = 'translate(0px, 0px) scale(1)';
            });
        });
    }

    // Enhanced Card Hover
    enhanceCardHover(card, e) {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        card.style.setProperty('--hover-x', `${(x / rect.width) * 100}%`);
        card.style.setProperty('--hover-y', `${(y / rect.height) * 100}%`);
        
        // Add dynamic glow effect
        card.style.boxShadow = `
            0 25px 50px rgba(0, 212, 255, 0.15),
            0 0 100px rgba(0, 212, 255, 0.1),
            ${x - rect.width/2}px ${y - rect.height/2}px 50px rgba(0, 212, 255, 0.2)
        `;
    }

    updateCardTilt(card, e) {
        const rect = card.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        
        const rotateX = (e.clientY - centerY) / 20;
        const rotateY = (e.clientX - centerX) / 20;
        
        card.style.transform = `
            perspective(1000px) 
            rotateX(${-rotateX}deg) 
            rotateY(${rotateY}deg) 
            translateY(-15px) 
            scale(1.02)
        `;
    }

    resetCardTilt(card) {
        card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px) scale(1)';
        card.style.boxShadow = '';
    }

    triggerElementAnimation(element) {
        element.style.animation = 'none';
        element.offsetHeight; // Trigger reflow
        element.style.animation = 'cardLoad 1s ease-out forwards';
    }
}

// Add custom CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes cardLoad {
        0% {
            opacity: 0;
            transform: perspective(1000px) rotateX(-20deg) translateY(50px) scale(0.9);
            filter: blur(10px);
        }
        100% {
            opacity: 1;
            transform: perspective(1000px) rotateX(0deg) translateY(0px) scale(1);
            filter: blur(0px);
        }
    }
    
    .animate-in {
        animation: cardLoad 1s ease-out forwards;
    }
    
    .floating-shape {
        pointer-events: none !important;
    }
`;
document.head.appendChild(style);

// Initialize animations when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CipherSphereAnimations();
});

// Additional Matrix Rain Effect
function createMatrixRain() {
    const matrixContainer = document.createElement('div');
    matrixContainer.className = 'matrix-rain';
    document.body.appendChild(matrixContainer);
}

// Initialize Matrix Rain
document.addEventListener('DOMContentLoaded', createMatrixRain);
