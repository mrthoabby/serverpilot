// ServerPilot Dashboard JavaScript
(function() {
    'use strict';

    var loginForm = document.getElementById('loginForm');
    var loginSection = document.getElementById('login-form');
    var dashboardSection = document.getElementById('dashboard');
    var contentDiv = document.getElementById('content');

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var username = document.getElementById('username').value;
            var password = document.getElementById('password').value;
            login(username, password);
        });
    }

    function login(username, password) {
        fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password })
        })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (data.success) {
                loginSection.style.display = 'none';
                dashboardSection.style.display = 'block';
                loadContainers();
            } else {
                alert('Login failed: ' + (data.error || 'unknown error'));
            }
        })
        .catch(function() {
            alert('Login request failed');
        });
    }

    window.logout = function() {
        fetch('/api/logout', { method: 'POST' })
        .then(function() {
            dashboardSection.style.display = 'none';
            loginSection.style.display = 'block';
            contentDiv.innerHTML = '';
        });
    };

    window.loadContainers = function() {
        fetch('/api/containers')
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (!data.success) {
                contentDiv.innerHTML = '<p>Error loading containers</p>';
                return;
            }
            var containers = data.data || [];
            var html = '<h2>Docker Containers</h2>';
            html += '<table><tr><th>Name</th><th>Image</th><th>Status</th><th>Ports</th></tr>';
            containers.forEach(function(c) {
                var ports = (c.ports || []).map(function(p) {
                    return p.host_port + ':' + p.container_port;
                }).join(', ');
                html += '<tr><td>' + escapeHtml(c.name) + '</td>';
                html += '<td>' + escapeHtml(c.image) + '</td>';
                html += '<td>' + escapeHtml(c.status) + '</td>';
                html += '<td>' + escapeHtml(ports) + '</td></tr>';
            });
            html += '</table>';
            contentDiv.innerHTML = html;
        });
    };

    window.loadSites = function() {
        fetch('/api/sites')
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (!data.success) {
                contentDiv.innerHTML = '<p>Error loading sites</p>';
                return;
            }
            var sites = data.data || [];
            var html = '<h2>Nginx Sites</h2>';
            html += '<table><tr><th>Domain</th><th>Listen</th><th>Proxy</th><th>SSL</th><th>Enabled</th></tr>';
            sites.forEach(function(s) {
                html += '<tr><td>' + escapeHtml(s.domain) + '</td>';
                html += '<td>' + escapeHtml(s.listen_port) + '</td>';
                html += '<td>' + escapeHtml(s.proxy_pass) + '</td>';
                html += '<td>' + (s.ssl_enabled ? '<span class="ssl-enabled">Yes</span>' : '<span class="ssl-disabled">No</span>') + '</td>';
                html += '<td>' + (s.enabled ? 'Yes' : 'No') + '</td></tr>';
            });
            html += '</table>';
            contentDiv.innerHTML = html;
        });
    };

    window.loadMappings = function() {
        fetch('/api/mappings')
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (!data.success) {
                contentDiv.innerHTML = '<p>Error loading mappings</p>';
                return;
            }
            var mappings = data.data || [];
            var html = '<h2>Container-Site Mappings</h2>';
            html += '<table><tr><th>Container</th><th>Port</th><th>Domain</th><th>SSL</th></tr>';
            mappings.forEach(function(m) {
                html += '<tr><td>' + escapeHtml(m.container_name) + '</td>';
                html += '<td>' + escapeHtml(m.container_port) + '</td>';
                html += '<td>' + escapeHtml(m.nginx_domain) + '</td>';
                html += '<td>' + (m.ssl_enabled ? 'Yes' : 'No') + '</td></tr>';
            });
            html += '</table>';
            contentDiv.innerHTML = html;
        });
    };

    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();
