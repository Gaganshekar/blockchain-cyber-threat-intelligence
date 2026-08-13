// ==========================================
// Blockchain Cyber Threat Intelligence
// script.js
// ==========================================

// Smooth scrolling for navigation
document.querySelectorAll("a[href^='#']").forEach(anchor => {

    anchor.addEventListener("click", function(e) {

        e.preventDefault();

        document.querySelector(this.getAttribute("href"))
            .scrollIntoView({
                behavior: "smooth"
            });

    });

});

// ==========================================
// Counter Animation
// ==========================================

const counters = document.querySelectorAll(".stat-box h2");

counters.forEach(counter => {

    const updateCounter = () => {

        const text = counter.innerText;

        const target = parseInt(text.replace(/\D/g, ""));

        if (isNaN(target)) return;

        let current = parseInt(counter.getAttribute("data-count")) || 0;

        const increment = Math.ceil(target / 60);

        if (current < target) {

            current += increment;

            if (current > target) current = target;

            counter.setAttribute("data-count", current);

            if (text.includes("%")) {

                counter.innerText = current + "%";

            } else if (text.includes("+")) {

                counter.innerText = current + "+";

            } else {

                counter.innerText = current;

            }

            setTimeout(updateCounter, 25);

        }

    };

    updateCounter();

});

// ==========================================
// Fade-in Animation
// ==========================================

const observer = new IntersectionObserver(entries => {

    entries.forEach(entry => {

        if (entry.isIntersecting) {

            entry.target.style.opacity = "1";

            entry.target.style.transform = "translateY(0)";

        }

    });

});

document.querySelectorAll(".card").forEach(card => {

    card.style.opacity = "0";

    card.style.transform = "translateY(40px)";

    card.style.transition = "0.6s ease";

    observer.observe(card);

});

// ==========================================
// Navbar Shadow on Scroll
// ==========================================

window.addEventListener("scroll", () => {

    const header = document.querySelector("header");

    if (window.scrollY > 50) {

        header.style.boxShadow = "0 0 20px rgba(0,200,255,.4)";

    } else {

        header.style.boxShadow = "none";

    }

});

// ==========================================
// Form Validation
// ==========================================

const forms = document.querySelectorAll("form");

forms.forEach(form => {

    form.addEventListener("submit", function(e) {

        const inputs = form.querySelectorAll("input, textarea, select");

        let valid = true;

        inputs.forEach(input => {

            if (input.hasAttribute("required") &&
                input.value.trim() === "") {

                valid = false;

                input.style.border = "2px solid red";

            } else {

                input.style.border = "1px solid #333";

            }

        });

        if (!valid) {

            e.preventDefault();

            alert("Please fill in all required fields.");

        }

    });

});

// ==========================================
// Button Click Effect
// ==========================================

document.querySelectorAll(".btn, .btn2, .submit-btn").forEach(button => {

    button.addEventListener("click", function() {

        this.style.transform = "scale(0.96)";

        setTimeout(() => {

            this.style.transform = "";

        }, 120);

    });

});

// ==========================================
// Highlight Active Navigation Link
// ==========================================

const currentPage = window.location.pathname;

document.querySelectorAll("nav a").forEach(link => {

    if (link.getAttribute("href") === currentPage) {

        link.style.color = "#00c8ff";

        link.style.fontWeight = "700";

    }

});

// ==========================================
// Console Message
// ==========================================

console.log("Blockchain Cyber Threat Intelligence Platform Loaded Successfully.");