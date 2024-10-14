
        let currentIndex = 0;

        function updateCarousel() {
            const carouselItems = document.querySelectorAll('.carousel-item');
            carouselItems.forEach((item, index) => {
                item.classList.remove('active', 'left', 'right');
                if (index === currentIndex) {
                    item.classList.add('active');
                } else if (index === (currentIndex - 1 + carouselItems.length) % carouselItems.length) {
                    item.classList.add('left');
                } else if (index === (currentIndex + 1) % carouselItems.length) {
                    item.classList.add('right');
                }
            });
        }

        function moveNext() {
            const carouselItems = document.querySelectorAll('.carousel-item');
            currentIndex = (currentIndex + 1) % carouselItems.length;
            updateCarousel();
        }

        function movePrev() {
            const carouselItems = document.querySelectorAll('.carousel-item');
            currentIndex = (currentIndex - 1 + carouselItems.length) % carouselItems.length;
            updateCarousel();
        }

        window.onload = updateCarousel;