
$(document).ready(function(){
  setBanner();
});

function setBanner() {
  try {
    var element = document.getElementById("banner-placeholder");
    console.log("Loading banner temps");
    element.load("templates/banner.html");
  }
  catch(err) {
    console.log("Error hit");
    // $("#banner-placeholder").className = "topnav";  
    // var element = document.getElementById("banner-placeholder");
    // element.classList.add("topnav");
  }
}

function infiniteScroll() {
  var page=1;
  window.onscroll = function(ev) {
    if ((window.innerHeight + window.scrollY) >= document.body.offsetHeight) {
      ifrm = document.createElement("IFRAME"); 
      ifrm.setAttribute("resume_page", page+".html"); 
      ifrm.style.width = 100+"%"; 
      ifrm.style.height = 800+"px"; 
      document.body.appendChild(ifrm); 
      page++
    }
  };
}

// $(document).ready(function(){
//   $("#footer").load("");
// });

$(document).ready(function(){
  $("#templateContainer").load("templates/landing_page.html");
});

// $(document).ready(function(){
//   $("#login-template").load("templates/landing_page.html");
// });

// $(document).ready(function(){
//   $("#signup-template").load("templates/signup.html");
// });

// $(document).ready(function(){
//   $("#reset-password-template").load("templates/reset_password.html");
// });

// When a user clicks on a button, all <p> elements will be hidden:

// Example
$(document).ready(function(){
  $("#hideable").click(function(){
    $("p").hide();
  });
});


//<-- PROJECT CAROUSEL FUNCTIONS -->
// tab-switcher.js

//<-- ENDPROJECT CAROUSEL FUNCTIONS -->