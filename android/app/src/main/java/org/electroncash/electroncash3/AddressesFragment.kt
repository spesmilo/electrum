package org.electroncash.electroncash3

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup


class AddressesFragment : MainFragment() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title.value = getString(R.string.addresses)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_addresses, container, false)
    }

}
