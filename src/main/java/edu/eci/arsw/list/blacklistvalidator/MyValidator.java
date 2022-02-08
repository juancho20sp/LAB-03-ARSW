package edu.eci.arsw.list.blacklistvalidator;

import edu.eci.arsw.list.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.LinkedList;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MyValidator implements Runnable {
    int start;
    int end;
    int maliciousOccurrences;
    int checkedListsCount;
    int alarmCount;
    String ipaddress;
    Thread myThread;
    HostBlackListsValidator hostBlacklistValidator;
    HostBlacklistsDataSourceFacade skds;
    LinkedList<Integer> blackListOcurrences;

    private boolean exit;

    MyValidator(int start, int end, HostBlacklistsDataSourceFacade skds, int alarmCount, String ipaddress,
                HostBlackListsValidator hostBlacklistValidator) {
        this.start = start;
        this.end = end;
        this.skds = skds;
        this.alarmCount = alarmCount;
        this.ipaddress = ipaddress;
        this.hostBlacklistValidator = hostBlacklistValidator;

        this.maliciousOccurrences = 0;
        this.checkedListsCount = 0;

        this.blackListOcurrences = new LinkedList<>();
        this.myThread = new Thread(this, "Holi crayoli");

        exit = false;
    }

    @Override
    public void run() {
        while(!exit) {
            for (int i = this.start; this.maliciousOccurrences < this.alarmCount && i <= this.end; i++){
//                this.checkedListsCount += 1;

                if (exit) {
                    break;
                } else {
                    this.checkedListsCount += 1;
                }
                if (skds.isInBlackListServer(i, ipaddress)){

                    this.blackListOcurrences.add(i);

                    this.maliciousOccurrences += 1;
                }
            }
        }

        System.out.println("THREAD EXITED");

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});
    }

    public void stopThread() {
        exit = true;
    }

    public int getMaliciousOccurrences() {
        return this.maliciousOccurrences;
    }

    public  LinkedList<Integer> getBlackListOcurrences() { return this.blackListOcurrences; }

    public void startThread(){
        this.myThread.start();
    }

    public void runThread(){
        this.myThread.run();
    }

    public void joinThread() {
        try {
            this.myThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
}
