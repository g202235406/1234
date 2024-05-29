document.addEventListener('DOMContentLoaded', function() {
    var btn = document.getElementById('submit');
    btn.addEventListener('mouseenter', function() {
        this.classList.add('hover');
    });

    btn.addEventListener('mouseleave', function() {
        this.classList.remove('hover');
    });
    var enter = document.getElementById('password');
	enter.addEventListener('keypress', function(event) {
		 if (event.key === 'Enter') {
            event.preventDefault();
            btn.click();
        }
    });
    btn.addEventListener('click', function(event) {
        event.preventDefault();
        var id = document.getElementById('id').value;
        var password = enter.value;
		if (!id) {
            alert('id error');
            return;
        }
		else if (!password) {
            alert('pw error');
            return;
		}
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/login', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                var response = JSON.parse(xhr.responseText);
                if (response.message === 'success') {
                    alert('yes');
                } else {
                    window.location.reload();
                }
            }
        };
        var data = JSON.stringify({'id': id, 'password': password});
        xhr.send(data);
    });
});