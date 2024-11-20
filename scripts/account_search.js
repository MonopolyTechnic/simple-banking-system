const searchBar = document.getElementById('email')
const searchPreviewList = document.getElementById('emailSearchList');
const form = document.getElementById('search-form1');

let typingTimeout;
const delay = 1000; //time after you stop typing to make a search query
searchBar.addEventListener("input" , () => {
    // Clear the previous timeout (if any)
    clearTimeout(typingTimeout);

    // Set a new timeout
    typingTimeout = setTimeout(async () => {
        //after a 1 second delay of no typing, search database for email in form
        emailSearchList.innerHTML = ''; // Clear search results
        const form = document.getElementById('search-form1');
        const email = new FormData(form, null).get('email');
        const data = await fetch(`/list-potential-emails?email=${email}`).then(res => res.json()).catch(console.error);
        if(data){
            emailSearchList.style.display = 'block';
            data.forEach(email => {
                const li = document.createElement('li');
                li.classList.add('search-result-preview');
                li.textContent = email;
                emailSearchList.appendChild(li);
            });
        }
    }, delay);
});
searchPreviewList.addEventListener('click', (event) =>{
    if (event.target.tagName.toLowerCase() === 'li') {
        searchBar.value = event.target.textContent;
        form.onsubmit();
        searchPreviewList.innerHTML = '';
    }
})