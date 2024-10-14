const reportForm = document.querySelector('.unique-report-form');
const closeButton = document.querySelector('.unique-close-button');
function openForm() {
    reportForm.classList.add('active');
}

function closeForm() {
    reportForm.classList.remove('active'); 
}

closeButton.addEventListener('click', closeForm);

