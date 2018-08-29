package org.electroncash.electroncash3

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup


class WalletsFragment : MainFragment() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title.value = getString(R.string.offline)
        subtitle.value = getString(R.string.offline_subtitle)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_wallets, container, false)
    }

}
