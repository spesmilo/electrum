package org.electroncash.electroncash3

import android.databinding.DataBindingUtil
import android.databinding.ViewDataBinding
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup

// Based on https://medium.com/google-developers/android-data-binding-recyclerview-db7c40d9f0e4
abstract class BoundAdapter(val layoutId: Int)
    : RecyclerView.Adapter<BoundViewHolder>() {

    override fun getItemViewType(position: Int): Int {
        return layoutId
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): BoundViewHolder {
        val layoutInflater = LayoutInflater.from(parent.context)
        val binding = DataBindingUtil.inflate<ViewDataBinding>(
            layoutInflater, viewType, parent, false)
        return BoundViewHolder(binding)
    }

    override fun onBindViewHolder(holder: BoundViewHolder, position: Int) {
        holder.binding.setVariable(BR.model, getItem(position))
        holder.binding.executePendingBindings()
    }

    protected abstract fun getItem(position: Int): Any
}

class BoundViewHolder(val binding: ViewDataBinding)
    : RecyclerView.ViewHolder(binding.root)

