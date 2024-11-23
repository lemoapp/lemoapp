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



document.addEventListener("DOMContentLoaded", () => {
    const newsItems = [
      { img: "news1.jpg", title: "Exciting News Headline 1", summary: "This is a short summary of the first news.", link: "#" },
      { img: "news2.jpg", title: "Exciting News Headline 2", summary: "Short summary for the second news.", link: "#" },
      { img: "news3.jpg", title: "Breaking News Headline 3", summary: "Another exciting update for you.", link: "#" },
      { img: "news4.jpg", title: "Trending News Headline 4", summary: "Stay ahead with trending updates.", link: "#" },
      { img: "news5.jpg", title: "Global News Headline 5", summary: "International updates you can't miss.", link: "#" },
      { img: "news6.jpg", title: "Local News Headline 6", summary: "Everything happening around you.", link: "#" },
      { img: "news7.jpg", title: "Tech News Headline 7", summary: "Discover the latest in technology.", link: "#" },
      { img: "news8.jpg", title: "Finance News Headline 8", summary: "Updates on global financial markets.", link: "#" }
    ];
  
    let currentIndex = 0;
    let isPlaying = true;
    const container = document.querySelector(".news-container");
    const indicators = document.querySelectorAll(".indicator");
    const playPauseBtn = document.getElementById("playPauseBtn");
  
    function updateNews() {
      // Create sliding-out animation
      container.innerHTML = "";
      const nextNews1 = newsItems[currentIndex % newsItems.length];
      const nextNews2 = newsItems[(currentIndex + 1) % newsItems.length];
  
      container.innerHTML = `
        <div class="news-item slideInFromLeft">
          <img src="${nextNews1.img}" alt="${nextNews1.title}" class="news-image">
          <h3 class="news-title">${nextNews1.title}</h3>
          <p class="news-summary">${nextNews1.summary}</p>
          <a href="${nextNews1.link}" class="read-more">Read More</a>
        </div>
        <div class="news-item slideInFromRight">
          <img src="${nextNews2.img}" alt="${nextNews2.title}" class="news-image">
          <h3 class="news-title">${nextNews2.title}</h3>
          <p class="news-summary">${nextNews2.summary}</p>
          <a href="${nextNews2.link}" class="read-more">Read More</a>
        </div>
      `;
  
      updateIndicators();
      currentIndex += 2;
    }
  
    function updateIndicators() {
      indicators.forEach((indicator, index) => {
        indicator.classList.toggle("active", index === currentIndex / 2 % 4); // Adjust for 8 tabs
      });
    }
  
    function togglePlayPause() {
      isPlaying = !isPlaying;
      playPauseBtn.textContent = isPlaying ? "Pause" : "Play";
    }
  
    let interval = setInterval(() => {
      if (isPlaying) updateNews();
    }, 2000);
  
    playPauseBtn.addEventListener("click", togglePlayPause);
  });
  
  