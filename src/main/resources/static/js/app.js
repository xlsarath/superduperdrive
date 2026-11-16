// SuperDuperDrive front-end behaviour. Served from 'self' only (strict CSP, no inline script).
(function () {
    'use strict';

    const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;

    // Confirm destructive actions.
    document.querySelectorAll('form[data-sdd-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.dataset.sddConfirm)) {
                event.preventDefault();
            }
        });
    });

    // Note dialog: new vs edit.
    const noteModal = document.getElementById('noteModal');
    if (noteModal) {
        noteModal.addEventListener('show.bs.modal', function (event) {
            const trigger = event.relatedTarget;
            const editing = trigger && trigger.dataset.sddId;
            document.getElementById('note-id').value = editing ? trigger.dataset.sddId : '';
            document.getElementById('note-title').value = editing ? trigger.dataset.sddTitle : '';
            document.getElementById('note-description').value = editing ? trigger.dataset.sddBody : '';
            document.getElementById('noteModalLabel').textContent = editing ? 'Edit note' : 'New note';
        });
        noteModal.addEventListener('shown.bs.modal', function () {
            document.getElementById('note-title').focus();
        });
    }

    // Credential dialog: the password is never pre-filled; empty keeps the stored one.
    const credentialModal = document.getElementById('credentialModal');
    if (credentialModal) {
        credentialModal.addEventListener('show.bs.modal', function (event) {
            const trigger = event.relatedTarget;
            const editing = trigger && trigger.dataset.sddId;
            document.getElementById('credential-id').value = editing ? trigger.dataset.sddId : '';
            document.getElementById('credential-url').value = editing ? trigger.dataset.sddUrl : '';
            document.getElementById('credential-username').value = editing ? trigger.dataset.sddUsername : '';
            const password = document.getElementById('credential-password');
            password.value = '';
            password.required = !editing;
            document.getElementById('credential-password-help').classList.toggle('d-none', !editing);
            document.getElementById('credentialModalLabel').textContent = editing ? 'Edit credential' : 'New credential';
        });
        credentialModal.addEventListener('shown.bs.modal', function () {
            document.getElementById('credential-url').focus();
        });
    }

    // Reveal / hide a credential's password (POST with the CSRF header; response is no-store).
    document.querySelectorAll('.reveal-credential').forEach(function (button) {
        button.addEventListener('click', async function () {
            const row = button.closest('tr');
            const cipher = row.querySelector('.credential-password');
            const revealed = row.querySelector('.credential-revealed');
            if (!revealed.classList.contains('d-none')) {
                revealed.textContent = '';
                revealed.classList.add('d-none');
                cipher.classList.remove('d-none');
                button.querySelector('i').className = 'bi bi-eye';
                return;
            }
            button.disabled = true;
            try {
                const headers = {};
                if (csrfHeader && csrfToken) {
                    headers[csrfHeader] = csrfToken;
                }
                const response = await fetch(button.dataset.sddRevealUrl, {
                    method: 'POST', headers: headers, credentials: 'same-origin'
                });
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                const body = await response.json();
                revealed.textContent = body.password;
                revealed.classList.remove('d-none');
                cipher.classList.add('d-none');
                button.querySelector('i').className = 'bi bi-eye-slash';
            } catch (error) {
                window.alert('The password could not be decrypted.');
            } finally {
                button.disabled = false;
            }
        });
    });

    // Client-side size check mirrors the server limit, to fail fast on huge files.
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function (event) {
            const input = document.getElementById('fileUpload');
            const max = Number(uploadForm.dataset.sddMaxBytes);
            if (input.files.length && input.files[0].size > max) {
                event.preventDefault();
                window.alert('That file is larger than the 50 MB upload limit.');
            }
        });
    }

    // Copy-to-clipboard buttons.
    document.querySelectorAll('[data-sdd-copy]').forEach(function (button) {
        button.addEventListener('click', async function () {
            const source = document.querySelector(button.dataset.sddCopy);
            try {
                await navigator.clipboard.writeText(source.textContent.trim());
                button.innerHTML = '<i class="bi bi-check2 me-1"></i>Copied';
            } catch (error) {
                window.getSelection().selectAllChildren(source);
            }
        });
    });
}());
