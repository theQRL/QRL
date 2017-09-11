// Current detail wallet address
var currentDetailAddress = 0;

// Manage view state
// 0 = list addresses
// 1 = show single address
// 2 = show node stats
// 3 = recover address
var viewState = 0;

// Init Transactions table
var TransT = $("#TransT").DataTable();


// Modal to show address recovery result
function drawRecoverResult(result) {

    // Show modal with results
    if(result.status === "success") {
        $('#domModalTitle').text('Address Recovery Successful');
        $('#domModalBody').html('Please ensure you keep a copy of these details in a secure location!<br />' +
                                '<b>Address: </b><a href="http://qrlexplorer.info/search.html#'+result.recoveredAddress+'" target="_blank">'+result.recoveredAddress+'</a><br />'+
                                '<b>Hexseed: </b>' + result.hexseed+'<br />'+
                                '<b>Mnemonic: </b>' + result.mnemonic+'<br />'
                                );

        $('#domModal').modal('show');

        // Hide loading pane
        $('.dimmer').hide();
        $('#dimmerText').text("Please wait ...");

        // Show addresses
        getAddresses();
    } else {
        $('#domModalTitle').text('Recovery Failed!');
        $('#domModalBody').html('<b>Error: </b>'+result.message);

        $('#domModal').modal('show');

        // Hide loading pane
        $('.dimmer').hide();
        $('#dimmerText').text("Please wait ...");
    }
}


// Recovers the wallet!
function recoverAddress() {
    $('.dimmer').show();
    $('#dimmerText').text("Please wait ... this can take a while!");

    var type = $('#restoretype').val();
    var words = $('#words').val();
    var hexseed = $('#hexseed').val();

    $.ajax({
        url: './webwallet-recover',
        dataType: 'json',
        contentType: 'application/json',
        type: "POST",
        data: JSON.stringify( { "type": type, "words": words, "hexseed": hexseed } ),
        processData: false,
        success: function(data) {
            drawRecoverResult(data);
        },
        error: function(data) {
            drawRecoverResult(data);
        }
    });
}

// Toggles which texbox to show on restore page.
function toggleRestoreType() {
    selectedRestoreType = $("#restoretype").val();

    if(selectedRestoreType === "mnemonic") {
        $('#restoreHex').hide();
        $('#restoreMnemonic').show();
    } else if(selectedRestoreType === "hexseed") {
        $('#restoreHex').show();
        $('#restoreMnemonic').hide();
    } else {
        $('#restoreHex').hide();
        $('#restoreMnemonic').hide();
    }
}

// Show the recover address page
function recover() {
    // Change view state
    viewState = 3;

    // Clear form values
    $('#restoretype').val("");
    $('#hexseed').val("");
    $('#words').val("");

    // Hide restore types
    $('#restoreHex').hide();
    $('#restoreMnemonic').hide();

    // Hide other panes and show this one.
    $('#show-all-wallets').hide();
    $('#show-node-stats').hide();
    $('#show-wallet').hide();
    $('#show-recover').show();
}


// Draw a row in transactions table
function drawTransRow(timestamp, amount, txHashLink, block, txfrom, txto, fee, address, txnsubtype) {
    
    // Detect txn direction
    var txnDirection = "";
    if (address === txfrom) {
        // Sent from this wallet
        txnDirection = '<div style=\"text-align: center\"><i class=\"sign out icon\"></i></div>';
    } else {
        // Sent to this wallet
        txnDirection = '<div style=\"text-align: center\"><i class=\"sign in icon\"></i></td></div>';
    }

    // Override txnDirection is txnsubtype is COINBASE
    if(txnsubtype === "COINBASE") {
        txnDirection = '<div style=\"text-align: center\"><i class=\"yellow lightning icon\"></i></td></div>';
    }

    // Generate timestamp string
    var thisMoment = moment.unix(timestamp);
    var timeString  = moment(thisMoment).format("HH:mm D MMM YYYY");

    // Add row
    TransT.row.add([txHashLink, block, timeString, txfrom, txnDirection, txto, amount, fee]);
}

// Gets detail about the running node
function getNodeInfo(hideDimmer = false) {
    // Change view state
    viewState = 2;

    // Dimmer does not show for auto refreshes.
    if(hideDimmer === false) {
        $('.dimmer').show();
    }

    $('#show-wallet').hide();
    $('#show-all-wallets').hide();
    $('#show-recover').hide();
    $('#show-node-stats').show();


    /*
    {
      "status": "ok",
      "unmined": 14009974.73883562,
      "network": "qrl testnet",
      "block_reward": 0.84203832,
      "emission": 6990025.26116438,
      "stake_validators": 5,
      "epoch": 0,
      "block_time": 50110414.432299145,
      "version": "alpha/0.27a",
      "staked_percentage_emission": 70.82,
      "blockheight": 30,
      "nodes": 6,
      "block_time_variance": 1503311097.9484582,
      "network_uptime": 8594.410389661789
    }
    */
    $.ajax({
        url: 'http://127.0.0.1:8080/api/stats',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            $('.dimmer').hide();


            $('#network').text(':' + data.network);
            var x = moment.duration(data.network_uptime,'seconds').format("d[d] h[h] mm[min]");
            $('#uptime').text(x);
            $('#nodes').text(data.nodes);
            var x = moment.duration(data.block_time_variance,'seconds');
            x = Math.round(x/10)/100;
            $('#variance').text(x + 's');
            var x = moment.duration(data.block_time,'seconds').format("s[s]");
            $('#blocktime').text(x);
            $('#blockheight').text(data.blockheight);
            $('#validators').text(data.stake_validators);
            $('#PCemission').text(data.staked_percentage_emission + '%');
            $('#epoch').text(data.epoch);
            var x = data.emission;
            x = (Math.round(x * 10000)) / 10000;
            $('#emission').text(x);
            var x = data.unmined;
            x = (Math.round(x * 10000)) / 10000;
            $('#unmined').text(x);
            $('#reward').text(data.block_reward);
            $('#nodeversion').text(data.version);
        },
        error: function(data) {
            $('.dimmer').hide();
        }
    });

    // Mempool transactions
    $.ajax({
        url: './webwallet-mempool',
        dataType: 'text',
        type: "GET",
        success: function(data) {
            $('#mempooltransactions').text(data);
        },
        error: function(data) {
            $('.dimmer').hide();
        }
    });

    // Sync status
    $.ajax({
        url: './webwallet-sync',
        dataType: 'text',
        type: "GET",
        success: function(data) {
            $('#syncstatus').text(data);
        },
        error: function(data) {
            $('.dimmer').hide();
        }
    });

}

// Draws all addresses in wallet file to page.
function drawAddresses(addresses) {
    // Change view state
    viewState = 0;

    // Clear list first
    $('#walletlist').empty();

    // Loop all wallets, and present them
    var addressIndex = 0;
    $.each(addresses, function() {

        var thisAddress = this[0];
        var thisBalance = this[3];

        $('#walletlist').append(
            '<div class="event"><div class="content"><div class="summary"><div class="ui horizontal label" style="background-color:#d5a500;">'
            + addressIndex
            + '</div><b style="font-size:1.4em"><a onclick="showAddress('+ addressIndex +')">'
            + thisAddress +
            '</a></b><br>'
            + thisBalance +
            '</div></div></div><div class="ui divider"></div>'
        );

        // Increment address index id
        addressIndex += 1;
    });

    // Remove dimmer
    $('.dimmer').hide();
    $('#dimmerText').text("Please wait ...");
}

// Queries a list of all addresses from wallet, and passing to draw function to rendor to screen
function getAddresses(hideDimmer = false) {

    // Dimmer does not show for auto refreshes.
    if(hideDimmer === false) {
        $('.dimmer').show();
    }

    $('#show-wallet').hide();
    $('#show-node-stats').hide();
    $('#show-recover').hide();
    $('#show-all-wallets').show();

    $.ajax({
        url: './webwallet-addresses',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            drawAddresses(data);
        },
        error: function(data) {
            drawAddresses(data);
        }
    });
}



// Creates a new XMSS 8000sig address in local wallet, then refreshes addresses on page.
function createNewAddress() {
    $('.dimmer').show();
    $('#dimmerText').text("Please wait ... this can take a while!");
    $.ajax({
        url: './webwallet-create-new-address',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            getAddresses();
        },
        error: function(data) {
           getAddresses();
        }
    });
}


// Draws address detail to page
function drawAddress(addresses, showAddressId, addressDetail, usdvalue) {
    // Change view state
    viewState = 1;

    // Clear list first
    $('#walletdetail').empty();

    // Get some detail about this address
    // For now we're only using the address, and signatures
    var addressIndex = 0;
    var thisAddress = '';
    var sigSplit;
    var pendingBalance;
    $.each(addresses, function() {
        if(addressIndex === showAddressId) {
            currentDetailAddress = showAddressId;

            thisAddress = this[0];
            var thisBalance = this[3];
            var thisType = this[2];
            var thisNonce = this[4];
            var thisSigs = this[5];

            // Split up signature result
            // signatures left: 7993 (7993/8000)
            sigSplit = thisSigs.split('(')[1]; // 7993/8000)
            sigSplit = sigSplit.split(')')[0]; // 7993/8000
            sigSplit = sigSplit.split('/'); // [0] = 7993, [1] = 8000

            // Grab pending balance
            // balance: 287.20450158(700.0)
            pendingBalance = thisBalance.split('(')[1]; // 700.0)
            pendingBalance = pendingBalance.split(')')[0]; // 700.0
        }

        // Increment address index id
        addressIndex += 1;
    });

    // Show address
    $('#addressHeading').text(thisAddress);

    // Only show these details if we get a successful reply from the API
    if(addressDetail.status === "ok") {
        $('#balance').text(addressDetail.state.balance);
        $('#pendingbalance').text(pendingBalance);
        $('#nonce').text(addressDetail.state.nonce);
        $('#transactions').text(addressDetail.state.transactions);
        $('#sigsremaining').text(sigSplit[0]);

        TransT.clear();
        _.each(addressDetail.transactions, function(object) {

            // Grab values from API
            var thisTimestamp = (object.timestamp === undefined) ? "Unknown" : object.timestamp;
            var thisAmount = (object.amount === undefined) ? "Unknown" : object.amount;
            var thisBlock = (object.block === undefined) ? "Unknown" : object.block;
            var thisTxHash = (object.txhash === undefined) ? "Unknown" : object.txhash;
            var thisTxFrom = (object.txfrom === undefined) ? "Unknown" : object.txfrom;
            var thisTxTo =  (object.txto === undefined) ? "Unknown" : object.txto;
            var thisFee = (object.fee === undefined) ? 0 : object.fee;
            var thisAddress = addressDetail.state.address;
            var thisSubType = (object.subtype === undefined) ? "Unknown" : object.subtype;

            // Generate links
            thisBlock = '<a target="_blank" href="http://qrlexplorer.info/block/'+thisBlock+'">'+thisBlock+'</a>';
            txHashLink = '<a target="_blank" href="http://qrlexplorer.info/tx/'+thisTxHash+'">'+thisTxHash+'</a>';
            thisTxFrom = '<a target="_blank" href="http://qrlexplorer.info/a/'+thisTxFrom+'">'+thisTxFrom+'</a>';
            thisTxTo = '<a target="_blank" href="http://qrlexplorer.info/a/'+thisTxTo+'">'+thisTxTo+'</a>';

            drawTransRow(thisTimestamp, thisAmount, txHashLink, thisBlock, thisTxFrom, thisTxTo, thisFee, thisAddress, thisSubType);
        });
        TransT.columns.adjust().draw(true);

        // Attempt to get USD Value of wallet
        $.ajax({
            url: 'http://cors-anywhere.herokuapp.com/https://www.folio.ninja/api/v1/quote?base=QRL&quote=USD&amount=' + addressDetail.state.balance,
            dataType: 'json',
            jsonpCallback: 'callback',
            success: function(folioNinjaReply) {
                $('#usdvalue').text("$" + folioNinjaReply.response.quote);
            }
        });
    } else {
        TransT.clear();
        TransT.columns.adjust().draw(true);
        $('#balance').text("0");
        $('#pendingbalance').text("0");
        $('#nonce').text("0");
        $('#transactions').text("0");
        $('#sigsremaining').text(sigSplit[0]);
        $('#usdvalue').text("0");
    }

    // Remove dimmer
    $('.dimmer').hide();
}

// Step 2 - grab details from local api
function showAddressStep2(addresses, addressIndex) {
    // Get wallet address
    var counter = 0;
    var thisAddress = '';
    $.each(addresses, function() {
        if(addressIndex === counter) {
            thisAddress = this[0];
        }
        counter += 1;
    });

    $.ajax({
        url: 'http://127.0.0.1:8080/api/address/' + thisAddress,
        success: function(addressDetail) {
            drawAddress(addresses, addressIndex, addressDetail);
        },
        error: function(addressDetail) {
            drawAddress(addresses, addressIndex, addressDetail);
        }
    });
}

// Gets details about a single address, and passes to draw function to rendor to screen.
function showAddress(addressIndex, hideDimmer = false) {

    // Dimmer does not show for auto refreshes.
    // Also don't reset data
    if(hideDimmer === false) {
        $('.dimmer').show();

        // Clear to and amount onload
        $('#to').val("");
        $('#amount').val("");
        $('#addressHeading').text("");
        $('#balance').text("");
        $('#pendingbalance').text("");
        $('#nonce').text("");
        $('#transactions').text("");
        $('#sigsremaining').text("");
        $('#usdvalue').text("");
    }

    // Change view
    $('#show-all-wallets').hide();
    $('#show-node-stats').hide();
    $('#show-recover').hide();
    $('#show-wallet').show();
    
    // Get addresses then draw
    $.ajax({
        url: './webwallet-addresses',
        dataType: 'json',
        type: "GET",
        success: function(addresses) {
            showAddressStep2(addresses, addressIndex);
        },
        error: function(addresses) {
            showAddressStep2(addresses, addressIndex);
        }
    });
}


// Modal to show txn result to screen
function drawTxnResult(txnResult) {

    // Refresh wallet page to update values
    showAddress(currentDetailAddress);

    // Show modal with results
    if(txnResult.status === "success") {
        $('#domModalTitle').text('Transaction Successful');
        $('#domModalBody').html('<b>TXN Hash: </b><a href="http://qrlexplorer.info/search.html#'+txnResult.txnhash+'" target="_blank">'+txnResult.txnhash+'</a><br />'+
                                '<b>From: </b>' + txnResult.from+'<br />'+
                                '<b>To: </b>' + txnResult.to+'<br />'+
                                '<b>Amount: </b>' + txnResult.amount+' Quanta<br />'
                                );

        $('#domModal').modal('show');
    } else {

        $('#domModalTitle').text('Transaction Failed!');
        $('#domModalBody').html('<b>Error: </b>'+txnResult.message);

        $('#domModal').modal('show');
    }

    // Hide loading pane
    $('.dimmer').hide();
}


// Creates a transaction in the network
function sendQuanta() {
    $('.dimmer').show();

    var from = currentDetailAddress;
    var to = $('#to').val();
    var amount = $('#amount').val();

    $.ajax({
        url: './webwallet-send',
        dataType: 'json',
        contentType: 'application/json',
        type: "POST",
        data: JSON.stringify( { "from": from, "to": to, "amount": amount } ),
        processData: false,
        success: function(data) {
            drawTxnResult(data);            
        },
        error: function(data) {
            drawTxnResult(data);
        }
    });
}


// Show addresses on ready
$( document ).ready(function() {
    // Hide the detail pane
    $('#show-wallet').hide();
    $('#show-node-stats').hide();
    $('#show-recover').hide();

    // Rendor addresses to screen.
    getAddresses();
});


// 20 second refresh
window.setInterval(function() {
    // Refresh addresses
    if(viewState === 0) {
        getAddresses(true);
    }

    // Refresh individual address view
    if(viewState === 1) {
        showAddress(currentDetailAddress, true);
    }

    // Refresh node stats
    if(viewState === 2) {
        getNodeInfo(true);
    }
}, 20000);
