package org.electroncash.electroncash3

import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.app.ActionBar
import android.support.v7.app.AppCompatActivity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup


class WalletsFragment : Fragment() {

    lateinit var actionBar: ActionBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar = (activity as AppCompatActivity).supportActionBar!!
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_wallets, container, false)
    }

    override fun onResume() {
        super.onResume()
        activity.setTitle(R.string.offline)
        actionBar.setSubtitle(R.string.offline_subtitle)
    }

    override fun onPause() {
        actionBar.setSubtitle(null)
        super.onPause()
    }
}
