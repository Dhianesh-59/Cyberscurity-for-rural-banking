RURAL DIGITAL BANKING - SETTINGS + UPI-STYLE DEMO PAYMENTS

FEATURES ADDED
- Settings page: change password, create/change a 4-digit demo transaction PIN, and save the notification preference.
- Payments page styled like a modern UPI app: choose a registered demo contact, enter an amount and note, confirm with the transaction PIN.
- Internal demo transfer between two RuralBank accounts, with balance validation and transaction records on both accounts.
- Transaction history page.
- Dashboard links for Settings, Payments and Transactions.
- Corrected the withdrawal template filename used by Flask.

IMPORTANT
This is a college project simulation. It transfers virtual balances only inside banking.db. It does not connect to UPI, PhonePe, a bank, or any real payment network. Never enter a real UPI PIN or bank credentials here. The notification setting is a saved preference; this project does not send SMS/push notifications.

HOW TO RUN ON WINDOWS
1. Extract this folder.
2. Open Command Prompt or the VS Code terminal in this folder (the folder containing app.py).
3. Create and activate a virtual environment (optional but recommended):
   py -m venv .venv
   .venv\Scripts\activate
4. Install dependency:
   py -m pip install -r requirements.txt
5. Start the application:
   py app.py
6. Open http://127.0.0.1:5000 in your browser.

HOW TO TEST PAYMENTS
1. Register and verify a demo account.
2. Register a second demo account in another browser/private window.
3. Sign in to the first account and use Deposit to add demo funds.
4. Open Settings and set a 4-digit demo transaction PIN.
5. Open Payments, select the second account from Registered contacts, enter amount and PIN, then confirm.
6. Open Transactions in both accounts to see the sender and receiver records.

RECIPIENT FORMAT
Use a registered username, account number, or username@ruralbank. The @ruralbank suffix is a demo identifier only, not a real UPI ID.

DATABASE
The supplied banking.db is retained to preserve the existing demo data. Back it up before testing payments, because demo transfers change account balances and transaction records.
