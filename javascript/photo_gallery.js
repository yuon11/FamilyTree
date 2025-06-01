// === List your image URLs here ===
const imageUrls = [
  "https://familytreeimages.s3.us-east-1.amazonaws.com/10.jpg",
  "https://familytreeimages.s3.us-east-1.amazonaws.com/IMG-20231202-WA0002.jpg",
  // ... add more
];

const gallery = document.getElementById("gallery");
const modal = document.getElementById("modal");
const modalImg = document.getElementById("modal-image");

let currentIndex = 0;

// Warn if gallery isnt found
if (!gallery) {
  console.error("Gallery container not found. Ensure your HTML has an element with id='gallery'");
}

if (gallery) {
  imageUrls.forEach((url, index) => {
    const img = document.createElement("img");
    if (img) {
      img.src = url;
      img.alt = `Photo ${index + 1}`;
      img.onerror = () => {
        console.warn(`Image failed to load: ${url}`);
        img.style.display = "none"; // Or show a fallback image
      };
      img.onclick = () => openModal(index);
      img.onerror = () => {
        img.src = 'fallback.jpg'; // Your placeholder image
      };

      gallery.appendChild(img);
    }
  });
} else {
  console.error("Cannot build gallery: missing #gallery container");
}

function openModal(index) {
  currentIndex = index;
  modal.style.display = "block";
  modalImg.src = imageUrls[index];
}

function closeModal() {
  modal.style.display = "none";
}

function changeImage(direction) {
  currentIndex += direction;
  if (currentIndex < 0) currentIndex = imageUrls.length - 1;
  if (currentIndex >= imageUrls.length) currentIndex = 0;
  modalImg.src = imageUrls[currentIndex];
}

// Optional: close modal on outside click
window.onclick = (e) => {
  if (e.target == modal) closeModal();
};