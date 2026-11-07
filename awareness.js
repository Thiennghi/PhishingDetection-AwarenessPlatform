/* Curated examples, available even without PHP or a database connection. */
window.AwarenessTopics = [
 ['Phishing','Account verification','“Your account is locked. Verify your password.”','Unexpected credential requests or a login link on an unrelated domain.','Open the service through your own bookmark and check there.','ftc_phishing'],
 ['Phishing','Deceptive domains','paypal.com.security-check.test','The brand appears before the actual destination domain.','Read the whole hostname. A brand name somewhere in a URL proves nothing.','ms_phishing'],
 ['Scam','Prize or advance fee','“Pay a processing fee to collect your prize.”','An unexpected reward comes with a demand for payment.','Pause and verify independently before sending money.','ftc_scams'],
 ['Scam','Task & job offers','“Deposit crypto to unlock your earnings.”','A supposed job requires money before you can get paid.','Check the employer independently and refuse pay-to-work requests.','ftc_task'],
 ['Scam','Changed payment details','“Send the invoice payment to our new account.”','A supplier requests a sudden change to banking instructions.','Call your known contact using a previously verified number.','fbi_bec'],
 ['Malware','Disguised downloads','invoice.pdf.exe','A familiar document name ends with an executable extension.','Do not run unexpected files; verify the sender separately.','ms_phishing'],
 ['Malware','Fake CAPTCHA','“Press Windows + R, paste, and run to verify.”','A verification page tells you to execute a command.','Close the page without running the command.','ftc_captcha'],
 ['Phishing','Delivery or toll text','“Pay today or face a penalty.”','An unsolicited text combines urgency with a payment link.','Use the delivery company or toll agency’s official app or site.','ftc_tolls'],
 ['Phishing','QR-code lure','“Scan here to restore access.”','A QR code hides the destination until scanned.','Check the destination before opening it or entering information.','ftc_qr'],
 ['Scam','Tech support impersonation','“Your computer is infected. Call us now.”','An unexpected warning requests payment or remote access.','Contact support through a channel you already trust.','ftc_tech']
];
window.renderAwareness = function () {
 const container = document.getElementById('awarenessTableContainerTab');
 if (!container) return;
 const term = (document.getElementById('awarenessSearch')?.value || '').toLowerCase();
 const rows = window.AwarenessTopics.filter(row => row.slice(0,5).join(' ').toLowerCase().includes(term));
 container.replaceChildren();
 const table = document.createElement('table'); table.className = 'awareness-table';
 const caption = document.createElement('caption'); caption.textContent = 'Threat patterns and safer next steps'; table.appendChild(caption);
 const head = document.createElement('thead'); const hr = document.createElement('tr');
 ['Threat / pattern','Example','What to look for','What to do'].forEach(text => {const th = document.createElement('th'); th.scope='col'; th.textContent=text; hr.appendChild(th);});
 head.appendChild(hr);table.appendChild(head);
 const body = document.createElement('tbody');
 rows.forEach(row => {
  const tr=document.createElement('tr');
  [row[0]+' · '+row[1],row[2],row[3],row[4]].forEach((text,i)=>{
   const cell=document.createElement('td');cell.textContent=text;
   if(i===3){const source=window.PhishingDataset.sources.find(s=>s.id===row[5]);if(source){const a=document.createElement('a');a.href=source.url;a.textContent='Read '+source.publisher+' guidance ↗';a.target='_blank';a.rel='noopener noreferrer';cell.appendChild(a);}}
   tr.appendChild(cell);
  });body.appendChild(tr);
 });
 table.appendChild(body);container.appendChild(table);
 if(!rows.length){const empty=document.createElement('p');empty.textContent='No matching topics. Try another keyword.';container.appendChild(empty);}
 const count=document.getElementById('awarenessCount');if(count)count.textContent=rows.length+' of '+window.AwarenessTopics.length+' topics';
};
document.addEventListener('DOMContentLoaded',()=>document.getElementById('awarenessSearch')?.addEventListener('input',window.renderAwareness));
