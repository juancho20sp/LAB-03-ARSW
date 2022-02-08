/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.list.blacklistvalidator;

import edu.eci.arsw.list.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator implements Runnable {
    int[] startValues;
    int[] endValues;
    int totalThreads;
    String ipaddress;
    HostBlacklistsDataSourceFacade skds;

    ArrayList<MyValidator> myThreads;
    Thread myThread = new Thread(this, "HBLV");

    int totalOccurrences = 0;
    LinkedList<Integer> blackListOccurrences = new LinkedList<>();

    private static final int BLACK_LIST_ALARM_COUNT=5;

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress){

        LinkedList<Integer> blackListOcurrences=new LinkedList<>();

        int ocurrencesCount=0;

        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount=0;

        for (int i=0;i<skds.getRegisteredServersCount() && ocurrencesCount<BLACK_LIST_ALARM_COUNT;i++){
            checkedListsCount++;

            if (skds.isInBlackListServer(i, ipaddress)){

                blackListOcurrences.add(i);

                ocurrencesCount++;
            }
        }

        if (ocurrencesCount>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});

        return blackListOcurrences;
    }

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @param totalThreads The number of threads that we will use
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int totalThreads){
        this.totalThreads = totalThreads;
        this.ipaddress = ipaddress;

        LinkedList<Integer> blackListOcurrences=new LinkedList<>();
        
        this.skds=HostBlacklistsDataSourceFacade.getInstance();

        // Calculate the intervals
        this.calculateDivisions(totalThreads);

        // Create threads
        this.createThreads(ipaddress);

        // Run threads
        this.startThreads();

//        return this.getBlackListOcurrences();
        return this.blackListOccurrences;
    }

    private void calculateDivisions(int totalThreads) {
        this.startValues = new int[totalThreads];
        this.endValues = new int[totalThreads];

        for(int i = 0; i < totalThreads; i++){
            startValues[i] = i * (this.skds.getRegisteredServersCount() / totalThreads);
            endValues[i] = startValues[i] + (this.skds.getRegisteredServersCount() / totalThreads);

            // TODO
            if (i != 0) {
                startValues[i] += 1;
            }

            if ((totalThreads % 2) != 0 && i == totalThreads - 1) {
                endValues[i] += this.skds.getRegisteredServersCount() % totalThreads;
            }
        }
    }

    private void createThreads(String ipaddress) {
        myThreads = new ArrayList<>();

        for(int i = 0; i < this.totalThreads; i++){
            myThreads.add(new MyValidator(this.startValues[i], this.endValues[i], this.skds, BLACK_LIST_ALARM_COUNT,
                    ipaddress, this));
        }
    }

    private void startThreads() {
        // Total Occurrences 2.0
        this.myThread.start();

        try {
            this.myThread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        for(MyValidator myValidator : myThreads) {
            myValidator.startThread();
        }
    }

    private LinkedList<Integer> getBlackListOcurrences() {
        LinkedList<Integer> finalList = new LinkedList<>();

        for(MyValidator myValidator : myThreads) {
            myValidator.joinThread();

            LinkedList<Integer> tempList = myValidator.getBlackListOcurrences();

            // Add each blacklisted value of each list to the 'finalList' list
            for(Integer value : tempList){
                finalList.add(value);
            }
        }

        return finalList;
    }

    private AtomicInteger getBlackListOcurrencesTest() {
        LinkedList<Integer> finalList = new LinkedList<>();

        AtomicInteger total = new AtomicInteger(0);

        for(MyValidator myValidator : myThreads) {
            //myValidator.joinThread();
            total.addAndGet(myValidator.getBlackListOcurrences().size());
        }

        return total;
    }

    private int getTotalMaliciousOccurrenes() {
        int total = 0;

        for (MyValidator myValidator : myThreads){
            myValidator.joinThread();

            total += myValidator.getMaliciousOccurrences();
        }

        return total;
    }

    public void stopThreads() {
        for(MyValidator myValidator : myThreads) {
            myValidator.stopThread();
        }

    }

    public void stopThreadsAndMarkAsNotTrustworthy() {
        for (MyValidator myValidator : myThreads){
            // TODO
        }
    }
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());


    @Override
    public void run() {
        System.out.println("Running main thread");
        System.out.println("Size: " + this.getBlackListOcurrences().size());
        System.out.println("Condition: " + (this.getBlackListOcurrences().size() < BLACK_LIST_ALARM_COUNT));

        int occurrences = 0;

        while(occurrences < BLACK_LIST_ALARM_COUNT) {
            occurrences = getBlackListOcurrencesTest().get();
            totalOccurrences = occurrences;

            System.out.println("Total occurrences: " + totalOccurrences);

            try {
                this.myThread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        this.stopThreads();


        if (totalOccurrences >= BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
            System.out.println("PEGRILOSO");

        } else{
            skds.reportAsTrustworthy(ipaddress);
            System.out.printf("NO PEGRILOSO");
        }

       // return this.getBlackListOcurrences();
    }
}
