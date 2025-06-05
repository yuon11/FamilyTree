// $(document).ready(function(){
//   $("#footer").load("");
// });

// $(document).ready(function(){
//   $("#templateContainer").load("templates/landing_page.html");
// });

// When a user clicks on a button, all <p> elements will be hidden:

// Example
$(document).ready(function(){
  $("#hideable").click(function(){
    $("p").hide();
  });
});

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