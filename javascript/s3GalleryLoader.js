// s3GalleryLoader.js

export async function loadImages(containerId = "gallery") {
    const { Amplify, Storage } = window.aws_amplify;

        Amplify.configure({
        Auth: {
            identityPoolId: 'us-east-1:0546aad4-a61a-474f-a906-2d40a1ac5be8',
            region: 'us-east-1',
        },
        Storage: {
            bucket: 'familytreeimages',
            region: 'us-east-1',
        },
    });
    
  const gallery = document.getElementById(containerId);
  if (!gallery) return;

  try {
    const result = await Storage.list(''); // list all items
    result.forEach(async (item) => {
      const url = await Storage.get(item.key);
      const img = document.createElement('img');
      img.src = url;
      img.classList.add('thumbnail');
      img.onclick = () => showFullImage(url);
      gallery.appendChild(img);
    });
  } catch (err) {
    console.error("Error loading images:", err);
    gallery.innerHTML = `<p class="error-message">⚠️ Unable to load images. Please ensure you are signed in.</p>`;
  }
}

function showFullImage(url) {
  // Replace with your own image modal viewer logic
  const modal = document.getElementById("image-modal");
  const modalImg = document.getElementById("modal-img");

  if (modal && modalImg) {
    modalImg.src = url;
    modal.style.display = "block";
  } else {
    alert("Full image view: " + url);
  }
}
