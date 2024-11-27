let slideIndex = 0;
showSlides();

// Function to show the slides
function showSlides() {
    let i;
    const slides = document.getElementsByClassName("mySlides");
    const dots = document.getElementsByClassName("dot");

    for (i = 0; i < slides.length; i++) {
        slides[i].style.display = "none";  
    }
    slideIndex++;
    if (slideIndex > slides.length) {slideIndex = 1}    

    for (i = 0; i < dots.length; i++) {
        dots[i].className = dots[i].className.replace(" active", "");
    }

    slides[slideIndex - 1].style.display = "block";  
    dots[slideIndex - 1].className += " active";
    
    setTimeout(showSlides, 4000); // Change image every 3 seconds
}

// Function to show the selected slide when clicking on a dot
function currentSlide(n) {
    slideIndex = n;
    showSlides();
}


  


   // Handle click events on deposit options
   document.getElementById('buyDollarOption').addEventListener('click', () => {
    // loadingSpinner.style.display = 'block';
    window.location.href = 'recieve.html'; 
});

document.getElementById('depositCryptoOption').addEventListener('click', () => {
    // Show the spinner

    // Simulate page navigation with a delay (replace with actual page navigation logic)
    window.location.href = 'crypto-deposit.html'; // Replace with your actual page navigation
});

// Hide spinner when the page has loaded completely
window.addEventListener('load', function () {
    loadingSpinner.style.display = 'none';
});



const depositButton = document.getElementById('depositButton');
const depositOverlay = document.getElementById('depositOverlay');
const closeOverlayButton = document.getElementById('closeOverlay');

// Show the overlay when the deposit button is clicked
depositButton.addEventListener('click', function() {
    console.log('Deposit button clicked'); // Debugging
    depositOverlay.classList.add('show');  // Add the 'show' class
    console.log('Overlay should slide into view now'); // Debugging
});

// Hide the overlay when the close button is clicked
closeOverlayButton.addEventListener('click', function() {
    console.log('Close button clicked'); // Debugging
    depositOverlay.classList.remove('show');  // Remove the 'show' class
    console.log('Overlay should slide out of view now'); // Debugging
});
  





// Toggle between Login and Signup Forms
document.getElementById('showSignup').addEventListener('click', (e) => {
  e.preventDefault();
  document.getElementById('loginForm').classList.remove('active');
  document.getElementById('signupForm').classList.add('active');
});

document.getElementById('showLogin').addEventListener('click', (e) => {
  e.preventDefault();
  document.getElementById('signupForm').classList.remove('active');
  document.getElementById('loginForm').classList.add('active');
});