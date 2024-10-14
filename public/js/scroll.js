$(document).ready(function(){
    $("a").on('click', function(event) {
      if (this.hash !== "") {
        event.preventDefault();
        var hash = this.hash;
        $('html, body').animate({
          scrollTop: $(hash).offset().top
        }, 800, function(){
          window.location.hash = hash;
        });
      }
    });
  });
  $(document).ready(function () {
    $(window).scroll(function () {
        var fadesSection = $('#fades').offset().top;
        if ($(window).scrollTop() > fadesSection) {
            $('#goTopBtn').fadeIn();
        } else {
            $('#goTopBtn').fadeOut();
        }
    });
    $('#goTopBtn').click(function () {
        $('html, body').animate({ scrollTop: 0 }, 800);
        return false;
    });
});
