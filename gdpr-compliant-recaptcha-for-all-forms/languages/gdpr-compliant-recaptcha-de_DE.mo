��    1      �  C   ,      8  8  9  �  r  #  H  �  l  J   5  @  �  -  �     �       
     =  '     e     |  
   �     �     �     �     �     �     �     �                 4      M      e      j      ~      �      �      �      �      �      �      �      �      !     
!  �   !  �   �!  3  `"  ^  �$  �   �%  n  �&    X(  H   ])     �)     �)  R  �)  �  	+    �,  3  �/  W  1  `   v3    �3  G  �8     .>     B>     a>  �  q>     Z@     w@     �@  ;   �@     �@  $   �@     �@     A     A     6A     LA  /   hA     �A     �A     �A     �A     �A  )   B     2B     @B     [B     vB     {B     �B  
   �B     �B     �B  �   �B  n   aC  �  �C  Q  �E  �   G  L  �G    ?I  q   KJ     �J     �J               /            (                     -           )                                      #   ,              %               0       $   	          
          *             1   .            +          "   '                &   !    <br>
                                                        <ol>
                                                            <li>Set this to a path and file name to store recently submitted puzzles</li>
                                                            <li>The current dir is the root directory of your Wordpress installation</li>
                                                            <li>Used hash-puzzles are saved and will not be re-used anymore</li> 
                                                            <li>This mechanism is important to avoid spamming during the period of validity of a puzzle, after it has been solved</li>
                                                            <li>Every 1000 entries the file is reseted</li>
                                                        </ol> <br>Custom the subject fields for your different forms, in order to see meaningfull titles on your saved messages page<br>
                        For each relevant field field:value add a new line<br> 
                        Example: subject<br>
                        The fieldname has to be the specific technical fieldname of the message which you want to flag<br>
                        If you don't know the exact technical fieldname of the respective field, you can get it this way:<br>
                        <ol>
                            <li>Tick the box for 'Save clean messages'</li>
                            <li>Post a message from the respective form</li>
                            <li>Open the <a href='%s'>"Messages" inbox</a> and open your message that has been saved</li>
                            <li>Look for the field you want to use for flagging, and take the name of the respective attribute without apostrophs</li>
                        </ol> <br>Set this to a random string in order to give some unknown salt into the puzzle. It increases security, as it can't be guessed from client-side
                                                    <br>By default, this salt is generated as a hash from the point in time of your installation <br>Set this to control the amount of computing power required to solve the hash-puzzle<br>
                                                        If you don't know about the concept of proof-of-work, don't change it<br>
                                                        Approximate number of hash guesses needed for difficulty target of:<br>
                                                        <ol>
                                                            <li>Difficulty 1-4: 10</li>
                                                            <li>Difficulty 5-8: 100</li>
                                                            <li>Difficulty 9-12: 1,000</li>
                                                            <li>Difficulty 13-16: 10,000</li>
                                                            <li>Difficulty 17-20: 100,000</li>
                                                            <li>Difficulty 21-24: 1,000,000</li>
                                                            <li>Difficulty 25-28: 10,000,000</li>
                                                            <li>Difficulty 29-32: 100,000,000</li>
                                                        </ol> <br>The time a hash-puzzle is valid and has to be computed and solved anew <br>This option is usefull if you want to flag spam via specific new post fields<br>
                            These fields can be used during further processing (i.e. a mailer, some routines to store messages in your database, a mail client, ...)<br>
                            <strong>Beware: </strong> This option overrides existing fields with the same name, which may affect further processing<br>
                            If you want to be sure, that you do not override existing fields. Check the technical field names of your messages, like described for the suffixes<br>
                            If you have different follow-up processings, which require for different specific fields to flag spam,<br>
                            you can add multiple fields<br>
                            For each combination of field:value add a new line<br> 
                            Example: spam_filter:spam<br>
                            A flagged spam message with the following POST attributes ...<br>
                            {'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there'}<br>
                            ... would turn into ...
                            {'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', 'message':'Hi there', 'spam_filter':'spam'}<br> <br>When you have multiple sources for incoming messages (i.e. a contact form, a form to buy products, comments),<br>
                                you should add a field:suffix combination for each source, if the technical field names differ<br>
                                For each combination of field:suffix, add a new line<br> 
                                Example:<br>
                                subject:[spam]<br>
                                title: [spam]<br>
                                The subject of a flagged spam message with the following text 'New Request from xxx' would turn into '[spam]New Request from xxx'<br>
                                Usually the 'subject field' is appropriate in order to apply rules in your mail client easily<br>
                                The fieldname has to be the specific technical fieldname of the message which you want to flag<br>
                                If you don't know the exact technical fieldnames of the respective forms, you can get them this way:<br>
                                <ol>
                                    <li>Tick the box for 'Save clean messages'</li>
                                    <li>Post a message from the respective form</li>
                                    <li>Open the <a href='%s'>"Messages" inbox</a> and open your message that has been saved</li>
                                    <li>Look for the field you want to use for flagging, and take the name of the respective attribute without apostrophs</li>
                                </ol> Action is invalid! Apply for WordPress-Login Block spam Congratualations! If you see this page, the installation is finished and the plugin should block all spam right now!
                                <ol>
                                <li>If you face any problems or bugs, please give me a note in the support forum and I will fix them asap.</li>
                                <li>If you are happy with this plugin, please rate it <a href="https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post">here</a>.</li>
                                </ol>
                                 Contcat Form 7 support Delete Difficulty Directory for used puzzles Field Fieldname:suffix to flag spam Flag spam messages Messages Move to Messages Move to Spam Move to Trash New "POST" fields to flag spam ReCaptcha GDPR Compliant ReCaptcha GDPR Messages Salt Save clean messages Save spam messages Save spam messages with flag Settings Settings saved! Simulate spam messages Spam Subject fields Time Window Trash Value Yes Yes<br>
                                                If you want to check that only spam messages are blocked. You can see your saved spam messages <a href='%s'>here</a> Yes<br>
                                        If you want to store your clean messages to the databse. You can see your saved clean messages <a href='%s'>here</a> Yes<br>
                                    If you just want to flag spam messages in a specific field or by creating a new field instead of blocking them<br>
                                    In this case you should disable 'Block spam'<br>
                                    This could be useful for example, if your message are routed to your mail-adress and you still want to get all mails, <br>
                                    but spam messages shall be flagged respectively and you use your mail programm to order the flagged mails into a spam folder Yes<br>
                                    When spam is identified, the contact form 7 processing is applied for a better contact form 7 integration<br>
                                    If you use contact form 7, this option is recommended<br>
                                    Does not affect messages that are not submitted via contact form 7 Yes<br>
                                Indicates whether spam messages shall be saved with, or without flag<br>
                                For testing whether the flagging works as desired, it may be usefull do save the messages with flags Yes<br> 
                        <strong>Beware</strong>: For every plugin that is securing the WP login I recommend to use this only,<br>
                        if you know how to switch it off without login. (i.e. by deleting the plugin files from your plugin directory)<br>
                        Because, if anything goes wrong the plugin will block your login Yes<br> If checked, each incoming submission shall be treadted as spam. This option can be used in order to test whether the flagging of a spam message works as desired. <br><strong>Do not forget to uncheck this option, as soon as your testing is done</strong> You have clicked pretty fast. Please try again, to proof beeing a Human! messages out of Project-Id-Version: 
PO-Revision-Date: 2022-11-23 08:57+0100
Last-Translator: 
Language-Team: 
Language: de
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=2; plural=(n != 1);
X-Generator: Poedit 3.2
X-Poedit-Basepath: ..
X-Poedit-KeywordsList: __
X-Poedit-SearchPath-0: .
 <br>
<ol>
<li>In dieser Datei werden kürzlich verwendete Puzzles gespeichert</li>
<li>Der Ausgangspfad ist das derzeitige Installationsverzeichnis ihrer Wordpressinstallation</li>
<li>Verwendete Puzzles werden gespeichert und dürfen nicht erneut verwendet werden</li> 
<li>Dieser Mechanismus ist wichtig um Spam zu vermeiden, der nach dem Lösen eines Puzzles mit diesem durchgeführt werden könnte </li>
<li>Nach 1000 Einträgen wird die Datei geleert </li>
</ol> <br>Legen Sie die Betreffzeilen für Ihre unterschiedlichen Formulare fest, um sinnvolle Titel in ihrem „Nachrichteneingang“ zu erhalten<br>
Fügen Sie für jedes Feld, dass Sie im Titel verwenden möchten den technischen Feldnamen in eine neue Zeile<br>
Beispiel:
Absender<br>
Betreff<br>
Wenn Sie die technischen Feldnamen der entsprechenden Formulare herausfinden möchten:<br>
<ol>
<li>Bestätigen Sie 'Echte Nachrichten speichern’ </li>
<li>Senden Sie eine Nachricht aus dem entsprechenden Formular </li>
<li>Öffnen Sie <a href='%s'>"Nachrichten"-Eingang</a> und dort die Nachricht, welche Sie soeben versandt haben
<li>Suchen Sie nach den Feldern, welche Sie zum Markieren verwenden möchten und entnehmen Sie den jeweiligen technischen Nmen ohne Apostroph</li>
</ol> <br>Fügen Sie hier eine zufällige Zeichenfolge ein, die als "unbekannter Schlüssel" im Puzzle verwendet werden soll. Diese Zeichenfolge erhöht die Sicherheit, da Sie vom Anwender nicht erraten werden kann
<br>Der bereits eingefügte Standardwert, wird als Hash-Wert vom Installationszeitpunkt eingefügt <br>Dieser Wert bestimmt die erforderliche Rechenleistungum das Hash-Puzzle zu lösen.<br>
Ändern Sie diesen Wert nicht, wenn Sie das Konzept von Proof-ow-Work nicht kennen<br>
Durchschnittliche Anzahl erforderlicher Versuche, die benötigt werden um das Schwierigkeitsziel zu erreichen:<br>
<ol>
<li>Schwierigkeit 1-4: 10</li>
<li>Schwierigkeit 5-8: 100</li>
<li>Schwierigkeit 9-12: 1,000</li>
<li>Schwierigkeit 13-16: 10,000</li>
<li>Schwierigkeit 17-20: 100,000</li>
<li>Schwierigkeit 21-24: 1,000,000</li>
<li>Schwierigkeit 25-28: 10,000,000</li>
<li>Schwierigkeit 29-32: 100,000,000</li>
</ol> <br>Die Zeit, die Hash-Puzzle gültig ist und nach der es neu erstellt und berechnet werden muss <br>Diese Option ist sinnvoll wenn Sie Spam-Nachrichten mit komplett neuen Post-Feldern markieren möchten<br>
Diese Felder können zum Beispiel in der weiteren Verarbeitung benötigt (z.B. Mailer, Plugins um Nachrichten in der Datenbank zu speichern, ein E-Mail-Programm mail client, ...)<br>
<strong>Vorsicht: </strong>  Diese Option überschreibt bereits vorhandene Felder mit demselben Namen<br>
Sie sollten unbedingt sicherstellen, dass Sie keine vorhandenen Feldnamen überschreiben, da dies die weitere Verarbeitung der Nachricht beeinflussen kann.<br>
Prüfen Sie daher die technischen Feldnamen wie unter “Spam-Nachrichten markieren“ bereits beschrieben<br>
Wenn Sie unterschiedliche Folgeverarbeitungen haben, die unterschiedliche Felder zur Markierung von Spam voraussetzen,<br>
Können Sie mehrere Felder angeben <br>
Fügen Sie für jede Kombination von Feld:Wert eine neue Zeile ein<br> 
Beispiel: Spam_Filter:Spam<br>
									Eine markierte Spam-Nachricht mit den folgenden Post-Feldern...<br>
									{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', Nachricht':'Hallo'}<br>
									... würde sich wie folgt ändern ...
									{'name': 'Matthias Nordwig', 'email':'matthias.nordwig@programmiere.de', Nachricht':'Hallo', 'spam_filter':'spam'}<br> <br>Wenn Sie mehrere Quellen für eingehende Nachrichten haben (z.B. Kontaktformulare, ein Formular um Produkte zu bestellen, Kommentare),<br>
ist es möglicherweise sinnvoll mehrere Kombinationen von Feld:Suffix für jede Quelle festzulegen, wenn die technischen Feldnamen der unterschiedlichen Formulare sich unterscheiden<br>
Fügen Sie für jede Kombination von Feldname:Suffix, eine neue Zeile hinzu<br> 
Beispiel: Betreff:[spam]<br>
Der Betreff einer markiereten Nachricht mit dem folgenden Text 'Neue Anfrage von xxx' würde sich zu entsprechend zu '[spam]Neue Anfrage von xxx' ändern<br>
Normalerweise ist das 'Betreff-Feld' am sinnvollsten um Regeln im E-Mail-Programm einfach anhand von Regeln zu filtern<br>
Bei dem zu verwendenden Feldnamen handelt es sich um den technischen Feldnamen der Nachricht, die sie markieren möchten<br>
Wenn Sie die genauen technischen Feldnamne ihrer ANchrichten nicht kennen, könenn SIe diese wie folgt herausfinden:<br>
<ol>
<li>Bestätigen Sie die Option 'Echte Nachrichten speichern'</li>
<li>Senden Sie das entsprechende Formular ab</li>
<li>Öffnen Sie <a href='%s'>"Nachrichten"-Eingang</a> und dort die Nachricht, welche Sie soeben versandt haben
<li>Suchen Sie nach den Feldern, welche Sie zum Markieren verwenden möchten und entnehmen Sie den jeweiligen technischen Nmen ohne Apostroph</li>
</ol> Aktion unzulässig! Für WordPress-Login verwenden Spam blockieren Herzlichen Glückwunsch! Wenn Sie diese Seite sehen, war die Installation erfolgreich und das Plugin sollte Spam bereits jetzt blocken.
<ol>
<li>Wenn Sie mit dem Plugin Probleme haben oder Bugs finden, teilen Sie mir diese bitte im Support-Forum mit und ich werde Sie schnellstmöglich lösen</li>
<li>Wenn Sie zufrieden mit dem Plugin sind, Bewerten Sie es bitte <a href="https://wordpress.org/support/plugin/gdpr-compliant-recaptcha-for-all-forms/reviews/#new-post">hier</a></li>
</ol>  Contact Form 7 unterstützen Löschen Schwierigkeit Datei für bereits verwendete Puzzle (darf nicht leer sein) Feld Feldname:Suffix um Spam zu markieren SPAM-Nachrichten markieren Nachrichten Zu Nachrichten verschieben Nach Spam verschieben Nach Papierkorb verschieben Neues "Post"-Feld zum Markieren von Nachrichten ReCaptcha DSGVO-konform ReCaptcha DSGVO Nachrichten Salt Echte Nachrichten speichern Spam-Nachrichten speichern Spam-Nachrichten mit Markierung speichern Einstellungen Einstellungen gespeichert! Spam-Nachrichten speichern Spam Betreffzeile Zeitfenster Papierkorb Wert Ja Ja<br>
Falls Sie überprüfen möchten, ob auch wirklich nur  Spam-Nachrichten geblockt werden, können Sie ihre geblockten Spam-Nachrichten speichern und <a href='%s'>hier</a> einsehen Yes<br>
Falls Sie echte Nachtrichten speichern möchten. Diese können Sie dann <a href='%s'>hier</a> aufrufen Ja<br>
Wenn Sie Spam-Nachrichten lieber in einem festzulegenden, oder neu zu schaffenden Feld als Spam markieren möchten<br>
In diesem Fall Sollten Sie 'Spam blockieren' abschalten<br>
Das ist zum Beispiel sinnvoll, wenn Sie Nachrichten per Mail empfangen und weiterhin alle Nachrichten erhalten möchten,<br>
jedoch SPAM-Nachrichten entsprechend markiert werden sollen und Sie Ihr E-Mail-Programm verwenden möchten um diese anhand der Markierung in einen Spam-Ordner zu verschieben Ja<br>
Nachdem Spam identifiziert wurde, wird eine spezifische Verarbeitung für Contact Form 7 vorgenommen, um eine bessere Integration in Contact Form 7 zu gewährleisten<br>
Wenn Sie Contact Form 7 benutzen wird diese Option empfohlen<br>
Nachrichten die nicht von einem Contact Form 7 - Formular versandt werden, sind nicht betroffen Ja<br>
Legt fest, ob Spam-Nachrichten mit, oder ohne Markierung gespeichert werden sollen<br>
Wenn Sie überprüfen möchten, ob das Markieren wie gewünscht funktioniert, ist es sinnvoll nachrichten einmal mit Markierung zu speichern Ja<br>
<strong>Beware</strong>: Für jedes Plugin, welches das WP-Login absichert empfehle ich, dieses nur zu nutzen,<br>
wenn bekannt ist wie man es zur Not abschaltet ohne sich einloggen zu müssen. (z.B. durch Löschen der Plugin-Dateien aus dem Plugin-Ordner)<br>
Denn, wenn etwas schief geht blockt das Plugin den Login-Bereich Ja<br> Wird diese Option gewählt, wird jedes abgesendete Formular als Spam klassifiziert. Diese Option kann dazu verwendet werden, um die Flagging-Einstellungen für Spam zu testen. <br><strong>Achtung: Nicht vergessen die Option nach dem Testen abzuwählen</strong> Sie haben sehr schnell geklickt! Bitte versuchen Sie es noch einmal, um sicherzustellen dass Sie ein Mensch sind! Nachrichten von 